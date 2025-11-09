import struct
import os
import json
import re
from io import BytesIO, FileIO


class AWB:
    ## 文件头部大小为0x10字节，其后依次为ID表和偏移量表，再之后为子文件
    ## 子文件根据『数据对齐偏移量』进行对齐

    def __init__(self, stream: str|bytes) -> None:
        if type(stream) == str:
            self.stream = FileIO(stream)
            self.filename = re.split(r"[/\\]", stream)[-1]
        else:
            self.stream = BytesIO(stream)
            self.filename = ""
        self.headerRead()

    def headerRead(self) -> None:
        ## 文件头读取，含文件头部标识(4字节)、版本号(1字节)、偏移量表中每个条目的字节大小(1字节)、
        ## ID表中每个条目的字节大小(2字节)、包含文件数量(4字节)、数据对齐偏移量(2字节)、EHCA解密用的subkey(2字节)
        ## 其后为ID表和偏移量表，偏移量表的数据数量比包含文件数量多1个，似乎用于指示最后一个子文件的结束位置(通常为文件末尾)
        ## vgmstream的注释中指出，表中的偏移量可能会错位，特别是首个偏移量可能会指向偏移量表末尾，此时需要配合数据对齐偏移量来计算首个子文件的起始位置的偏移量
        ## 经过观察，偏移量表中的偏移量可能指向上一个子文件的末尾，此时也需要配合数据对齐偏移量来计算下一个子文件的起始位置
        stream = self.stream
        offset = 0x00
        stream.seek(0)
        self.headerID = stream.read(4)

        if self.headerID == b"AFS2":
            #self.encrypted = False
            pass
        else:
            raise ValueError("invalid awb header")
        
        self.version            = struct.unpack("<B", stream.read(1))[0]
        self.offset_size        = struct.unpack("<B", stream.read(1))[0]
        self.audioid_size       = struct.unpack("<H", stream.read(2))[0]
        self.subfiles_count     = struct.unpack("<I", stream.read(4))[0]
        self.offset_alignment   = struct.unpack("<H", stream.read(2))[0]
        self.subkey             = struct.unpack("<H", stream.read(2))[0]
        offset += 0x10

        ## 读取ID表
        self.audioids = []
        if self.audioid_size == 0x02:
            for _ in range(0, self.subfiles_count):
                audioid = struct.unpack("<H", stream.read(2))[0]
                offset += 2
                self.audioids.append(audioid)
        elif self.audioid_size == 0x04:
            for _ in range(0, self.subfiles_count):
                audioid = struct.unpack("<I", stream.read(4))[0]
                offset += 4
                self.audioids.append(audioid)
        else:
            raise ValueError(f"unknown awb audio ID size: {self.audioid_size:02x}")
        
        ## 读取偏移量表
        self.audio_offsets = []
        if self.offset_size == 0x02:
            for _ in range(0, self.subfiles_count + 1):
                audioid = struct.unpack("<H", stream.read(2))[0]
                offset += 2
                self.audio_offsets.append(audioid)
        elif self.offset_size == 0x04:
            for _ in range(0, self.subfiles_count + 1):
                audioid = struct.unpack("<I", stream.read(4))[0]
                offset += 4
                self.audio_offsets.append(audioid)
        else:
            raise ValueError(f"unknown awb offset size: {self.offset_size:02x}")
        
        ## 此时的偏移量应小于或等于偏移量表首项
        if offset > self.audio_offsets[0]:
            raise ValueError("offset now should not be greater than audio_offsets[0]")
        
        ## 文件总大小应大于或等于偏移量表末项
        stream.seek(0, 2)
        if stream.tell() < self.audio_offsets[-1]:
            raise ValueError("awb file size should not be less than audio_offsets[-1]")
        
        ## 若偏移量表首项仅指向偏移量表末尾，则需要配合数据对齐偏移量来计算首个子文件的起始位置的偏移量
        ## 此处将计算大于等于『偏移量表首项』的最小的『数据对齐偏移量』整数倍，并将其作为新的『偏移量表首项』
        remainder = self.audio_offsets[0] % self.offset_alignment
        if remainder > 0:
            self.audio_offsets[0] = self.audio_offsets[0] - remainder + self.offset_alignment

    def extract(self, opt_dir, acb_data : dict|None = None) -> None:
        ## 从awb中解包音频，并输出至指定目录
        ## 音频文件名通过解析相应的acb文件获得，若无acb数据，则默认以『awb文件名_音频ID』作为文件名
        ## awb可打包不同类型的音频文件，文件的后缀名将由其类型决定，目前已处理的音频类型有：hca
        stream = self.stream
        for idx in range(0, self.subfiles_count):
            ## 检查偏移量表中的数值是否对齐（此数值可能为上一块数据的末尾），若否，则计算正确的起始位置
            ## 此处将计算大于等于『偏移量表数值』的最小的『数据对齐偏移量』整数倍，并将其作为『数据起始偏移量』
            remainder = self.audio_offsets[idx] % self.offset_alignment
            if remainder > 0:
                offset_start = self.audio_offsets[idx] - remainder + self.offset_alignment
            else:
                ## remainder == 0
                offset_start = self.audio_offsets[idx] 

            stream.seek(offset_start)
            sf_type = self.getFileType(stream.read(16))
            sf_name_suffix = self.fileSuffixSet(sf_type)
            if acb_data is None:
                sf_name = f"{self.filename}_{self.audioids[idx]:08x}.{sf_name_suffix}"
            else:
                #sf_name = f""
                pass
            stream.seek(offset_start)
            data = stream.read(self.audio_offsets[idx+1] - offset_start)
            with open(os.path.join(opt_dir, sf_name), "wb") as file:
                file.write(data)

    ## 根据文件头部判断文件类型
    def getFileType(self, header: bytes) -> str|None:
        if header.startswith(b"HCA\x00"):
            return "HCA"
        elif header.startswith(b"\xC8\xC3\xC1\x00"):
            return "EHCA"
        else:
            return None
        
    ## 根据文件类型设置文件后缀名
    def fileSuffixSet(self, sf_type: str|None) -> str:
        if sf_type in ("HCA", "EHCA"):
            return "hca"
        else:
            return "bin"

    ## 输出文件头数据，调试用
    def headerDataOutput(self, opt_path: str) -> None:
        headerID = self.headerID.decode()
        header_data = {"headerID":headerID, "version":self.version, "offset_size":self.offset_size, 
                       "audioid_size":self.audioid_size, "subfiles_count":self.subfiles_count, 
                       "offset_alignment":self.offset_alignment, "subkey":self.subkey, 
                       "audio_ids":self.audioids, "audio_offsets":self.audio_offsets
                       }
        
        with open(opt_path, "w", encoding="utf8") as file:
            json.dump(header_data, file, ensure_ascii=False, indent=4)


class AWBBuilder:
    ## 输入文件列表，将其中的文件打包为awb文件
    ## 不会检测文件类型，请自行确保其正确性
    ## 子文件ID默认为其序号，暂不支持自定义子文件ID

    ## subfiles为需要打包的文件列表，这一项是必要的
    ## version为版本号，此处仅影响文件头里的对应数据，不影响awb文件构建过程
    ## offset_size为偏移量表中每个条目的字节大小，一般为2或4
    ## audioid_size为ID表中每个条目的字节大小，一般为2或4
    ## offset_alignment为数据对齐偏移量，建议为0x10的整数倍
    ## subkey为EHCA解密用的subkey，若无此需要可默认其为0
    ## offset_mode为偏移量表生成模式，为0则指向上一个子文件的末尾，为1则指向对应子文件的开头；样本文件里的大多是指向上一个子文件末尾的，所以默认使用模式0
    def __init__(self, subfiles: list[str]|tuple[str], 
                 version: int=2, offset_size: int=0x04, audioid_size: int=0x04, 
                 offset_alignment: int=0x20, subkey: int=0x00, offset_mode: int=0) -> None:
        self.sunfiles = subfiles
        self.subfiles_count = len(subfiles)
        if self.subfiles_count > 0x0100000000:
            raise ValueError(f"too many subfiles: {self.subfiles_count}")

        if version < 0 or version > 0xFF:
            raise ValueError(f"unsupported version: {version}")
        self.version = version

        ## offset_size应为2或4；确定总文件最大大小
        if offset_size == 0x02:
            self.awb_file_size_max = 0xFFFF
            self.offset_size = offset_size
        elif offset_size == 0x04:
            self.awb_file_size_max = 0xFFFFFFFF
            self.offset_size = offset_size
        else:
            raise ValueError(f"unsupported offset size: {offset_size}")
        
        ## audioid_size应为2或4；确认文件数目是否在范围内
        if audioid_size == 0x02:
            if self.subfiles_count > 0x010000:
                raise ValueError(f"too many subfiles({self.subfiles_count}) when audio ID size is {audioid_size}")
            self.audioid_size = audioid_size
        elif audioid_size == 0x04:
            if self.subfiles_count > 0x0100000000:
                ## 上面文件数量处检查过了，这里不应该被执行
                raise ValueError(f"too many subfiles({self.subfiles_count}) when audio ID size is {audioid_size}")
            self.audioid_size = audioid_size
        else:
            raise ValueError(f"unsupported audio ID size: {audioid_size}")
        
        if offset_alignment <= 0 or offset_alignment > 0xFFFF:
            raise ValueError(f"unsupported offset alignment: {offset_alignment}")
        self.offset_alignment = offset_alignment
            
        if subkey < 0 or subkey > 0xFFFF:
            raise ValueError(f"unsupported subkey: {subkey}")
        self.subkey = subkey

        if offset_mode not in (0, 1):
            raise ValueError(f"unsupported offset mode: {offset_mode}")
        self.offset_mode = offset_mode

    ## 计算对齐偏移量
    def offsetAlignmentProcess(self, offset: int) -> int:
        remainder = offset % self.offset_alignment
        if remainder > 0:
            offset_start = offset - remainder + self.offset_alignment
        else:
            ## remainder == 0
            offset_start = offset
        return offset_start


    def build(self, opt_path: str) -> None:
        header_data = self.headerPrepare()
        offset_list_last_end = []
        offset_list_start = []

        offset = 0x00
        offset += len(header_data)
        offset_list_last_end.append(offset)
        offset_start = self.offsetAlignmentProcess(offset)
        offset_list_start.append(offset_start)

        ## 每写入完整的一段数据，就会在其后填充`00`字节至数据对齐偏移量的整数倍
        ## 偏移量表生成模式决定了在最后一个子文件之后是否进行字节填充
        with open(opt_path, "wb") as file:
            file.write(header_data)
            file.write(bytes(offset_start - offset))

            subfile_number = 1
            for subfile in self.sunfiles:
                with open(subfile, "rb") as sf:
                    sf.seek(0, 2)
                    sf_size = sf.tell()
                    sf.seek(0)
                    file.write(sf.read(sf_size))
                    offset = offset_start + sf_size
                    offset_start = self.offsetAlignmentProcess(offset)
                    offset_list_last_end.append(offset)
                    offset_list_start.append(offset_start)
                    if (subfile_number < self.subfiles_count) or (self.offset_mode == 1):
                        file.write(bytes(offset_start - offset))
                subfile_number += 1

            ## 写入偏移量表
            file.seek(0x10 + self.audioid_size*self.subfiles_count)
            if self.offset_size == 0x02:
                offset_type_fc = "<H"
            elif self.offset_size == 0x04:
                offset_type_fc = "<I"
            else:
                raise ValueError(f"unsupported offset size: {self.offset_size}")
            
            if self.offset_mode == 0:
                offset_list = offset_list_last_end
            elif self.offset_mode == 1:
                offset_list = offset_list_start
            else:
                raise ValueError(f"unsupported offset mode: {self.offset_mode}")
            
            for idx in range(0, self.subfiles_count + 1):
                file.write(struct.pack(offset_type_fc, offset_list[idx]))
                


    ## 生成文件头数据，写入文件头部标识(4字节)、版本号(1字节)、偏移量表中每个条目的字节大小(1字节)、
    ## ID表中每个条目的字节大小(2字节)、包含文件数量(4字节)、数据对齐偏移量(2字节)、EHCA解密用的subkey(2字节)
    ## 计算ID表和偏移量表大小，以`00`字节填充
    def headerPrepare(self) -> bytes:
        header_data = bytearray()
        header_data += b"AFS2"
        header_data += struct.pack("<B", self.version)
        header_data += struct.pack("<B", self.offset_size)
        header_data += struct.pack("<H", self.audioid_size)
        header_data += struct.pack("<I", self.subfiles_count)
        header_data += struct.pack("<H", self.offset_alignment)
        header_data += struct.pack("<H", self.subkey)

        if self.audioid_size == 0x02:
            audioid_type_fc = "<H"
        elif self.audioid_size == 0x04:
            audioid_type_fc = "<I"
        else:
            raise ValueError(f"unsupported audio ID size: {self.audioid_size}")
        
        for idx in range(0, self.subfiles_count):
            header_data += struct.pack(audioid_type_fc, idx)

        header_data += bytes(self.offset_size * (self.subfiles_count+1))

        return bytes(header_data)



