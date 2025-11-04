import struct
import os
import json
import re
from io import BytesIO, FileIO


class AWB:

    def __init__(self, stream: str|bytes) -> None:
        if type(stream) == str:
            self.stream = FileIO(stream)
            self.filename = re.split(r"[/\\]", stream)[-1]
        else:
            self.stream = BytesIO(stream)
            self.filename = ""
        self.headerRead()

    def headerRead(self) -> None:
        ## 文件头读取，含头部标识(4字节)、版本号(1字节)、偏移量表中每个条目的字节大小(1字节)、
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
        
        self.version = struct.unpack("<B", stream.read(1))[0]
        self.offset_size = struct.unpack("<B", stream.read(1))[0]
        self.audioid_size = struct.unpack("<H", stream.read(2))[0]
        self.subfiles_count = struct.unpack("<I", stream.read(4))[0]
        self.offset_alignment = struct.unpack("<H", stream.read(2))[0]
        self.subkey = struct.unpack("<H", stream.read(2))[0]
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
                       "audio_ids":self.audioids, "audio_offsets":self.audio_offsets}
        
        with open(opt_path, "w", encoding="utf8") as file:
            json.dump(header_data, file, ensure_ascii=False, indent=4)









