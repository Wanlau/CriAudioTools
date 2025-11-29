import struct
import re
import json
import base64
import copy
from io import BytesIO, FileIO
from enum import Enum, unique
from collections.abc import Buffer

## UTF表所包含的数据类型
## 这部分数据来自vgmstream
## 
## 有一种说法是此处的有符号/无符号类型应该反过来，但具体如何尚无定论
## 在aic的文件中出现了以0xFFFF和0xFFFFFFFF表示『无』情况，但不知道它是以满值表示『无』还是以-1表示『无』
## 在得到确定的结论之前，暂且与vgmstream保持一致
@unique
class UTFTableValueType(Enum):
    COLUMN_TYPE_UINT8           = 0x00
    COLUMN_TYPE_SINT8           = 0x01
    COLUMN_TYPE_UINT16          = 0x02
    COLUMN_TYPE_SINT16          = 0x03
    COLUMN_TYPE_UINT32          = 0x04
    COLUMN_TYPE_SINT32          = 0x05
    COLUMN_TYPE_UINT64          = 0x06
    COLUMN_TYPE_SINT64          = 0x07
    COLUMN_TYPE_FLOAT           = 0x08
    COLUMN_TYPE_DOUBLE          = 0x09
    COLUMN_TYPE_STRING          = 0x0a
    COLUMN_TYPE_VLDATA          = 0x0b
    COLUMN_TYPE_UINT128         = 0x0c # for GUIDs
    COLUMN_TYPE_UNDEFINED       = -1

class UTFTable:
    ## UTF表是CRI定义的一种数据结构，可嵌套
    ## 文件头部大小为0x20字节，其后依次为模式数据区域、行数据区域、字符串数据区域、字节数据区域

    def __init__(self, stream: str | Buffer, encoding: str="utf8") -> None:
        if type(stream) == str:
            self.stream = FileIO(stream)
            self.filename = re.split(r"[/\\]", stream)[-1]
        else:
            self.stream = BytesIO(stream)
            self.filename = ""
        self.headerRead()
        self.headerCheck()
        self.encoding = encoding
        self.table_name = self.stringDataGet(self.name_offset_rtst)
        self.parsed = False

    def headerRead(self) -> None:
        ## 文件头读取，大端序，含头部标识(4字节)、UTF表大小(4字节)、版本号(2字节)、
        ## 行数据区域偏移量(2字节)、字符串数据区域偏移量(4字节)、字节数据区域偏移量(4字节)、
        ## 表格名称相对于字符串数据区域头部的偏移量(4字节)、列数(2字节)、行宽(2字节)、行数(4字节)
        ## 表格名称偏移量是相对于字符串数据区域头部的
        ## 其它偏移量则默认以UTF表开头为基准点(注意其它偏移量及UTF表大小读取后需+8)
        stream = self.stream
        stream.seek(0)
        self.headerID = stream.read(4)

        if self.headerID == b"@UTF":
            #self.encrypted = False
            pass
        elif self.headerID == b"\x1f\x9e\xf3\xf5":
            #self.encrypted = True
            ## 似乎是加密的UTF表，暂不作处理
            raise ValueError("invalid utf table header")
        else:
            raise ValueError("invalid utf table header")
        
        self.table_size = struct.unpack(">I", stream.read(4))[0] + 0x08
        self.version = struct.unpack(">H", stream.read(2))[0]
        self.rows_offset = struct.unpack(">H", stream.read(2))[0] + 0x08
        self.strings_offset = struct.unpack(">I", stream.read(4))[0] + 0x08
        self.data_offset = struct.unpack(">I", stream.read(4))[0] + 0x08
        self.name_offset_rtst = struct.unpack(">I", stream.read(4))[0]
        self.columns_count = struct.unpack(">H", stream.read(2))[0]
        self.row_width = struct.unpack(">H", stream.read(2))[0]
        self.rows_count = struct.unpack(">I", stream.read(4))[0]

    ## 根据文件头数据计算各区域大小，并检查其是否合法
    def headerCheck(self) -> None:
        self.schema_size    = self.rows_offset - 0x20
        self.rows_size      = self.strings_offset - self.rows_offset
        self.strings_size   = self.data_offset - self.strings_offset
        self.data_size      = self.table_size - self.data_offset

        if self.schema_size < 0:
            raise ValueError(f"invalid schema size: {self.schema_size}")
        
        if (self.rows_size < 0) or (self.rows_size < self.rows_count*self.row_width):
            raise ValueError(f"invalid rows size: {self.rows_size}")
        
        if (self.strings_size < 0) or (self.strings_size < self.name_offset_rtst):
            raise ValueError(f"invalid strings size: {self.strings_size}")
        
        if self.data_size < 0:
            raise ValueError(f"invalid data size: {self.data_size}")

    def utfParse(self) -> None:
        stream = self.stream
        data_columns = []

        ## 模式数据区域解析，依次遍历各列的模式数据
        ## 每列的模式数据有数据信息(1字节)及列名偏移量(4字节)，以及常量数据(可选)
        ## 数据信息分为两部分，高4位数据标志(包含哪些数据)，低4位为类型标志
        ## 列名偏移量是相对于字符串数据区域头部的
        offset = 0x20
        offset_in_row = 0
        for _ in range(0, self.columns_count):
            if offset + 5 - 0x20 > self.schema_size:
                raise ValueError(f"schema offset out of bounds: {offset + 5 - 0x20:#x}")
            stream.seek(offset)
            info        = struct.unpack(">B", stream.read(1))[0]
            name_offset = struct.unpack(">I", stream.read(4))[0]
            offset += 5

            data_flag = info >> 4
            type_flag = info & 0x0F
            value_type = UTFTableValueType(type_flag)

            ## 处理数据标志，数据标志共4位
            ## 0x10位为列名，0x20位为常量数据，0x40为行数据，0x80位未知
            ## 目前常见的组合有『列名+常量』及『列名+行数据』
            ## 古早版本中出现过『列名+常量+行数据』的情况，但在新版中这被认为是无意义的
            ## 目前处理的情况有：『列名』(01)、『列名+常量』(03)、『列名+行数据』(05)
            data_flag_name = False
            data_flag_constant = False
            data_flag_row = False
            if data_flag == 0x01:
                data_flag_name = True
            elif data_flag == 0x03:
                data_flag_name = True
                data_flag_constant = True
            elif data_flag == 0x05:
                data_flag_name = True
                data_flag_row = True
            else:
                raise ValueError(f"unsupported data flag: {data_flag}")
            
            ## 处理类型标志
            if value_type == UTFTableValueType.COLUMN_TYPE_UINT8:
                value_size = 1
                value_type_fc = ">B"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT8:
                value_size = 1
                value_type_fc = ">b"
            elif value_type == UTFTableValueType.COLUMN_TYPE_UINT16:
                value_size = 2
                value_type_fc = ">H"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT16:
                value_size = 2
                value_type_fc = ">h"
            elif value_type == UTFTableValueType.COLUMN_TYPE_UINT32:
                value_size = 4
                value_type_fc = ">I"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT32:
                value_size = 4
                value_type_fc = ">i"
            elif value_type == UTFTableValueType.COLUMN_TYPE_UINT64:
                value_size = 8
                value_type_fc = ">Q"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT64:
                value_size = 8
                value_type_fc = ">q"
            elif value_type == UTFTableValueType.COLUMN_TYPE_FLOAT:
                value_size = 4
                value_type_fc = ">f"
            elif value_type == UTFTableValueType.COLUMN_TYPE_DOUBLE:
                value_size = 8
                value_type_fc = ">d"
            ## 注意，以下两种类型为变长类型，其在模式数据区域及行数据区域中仅存储起始偏移量等信息
            ## 『COLUMN_TYPE_STRING』为字符串，其数据本身存储于字符串数据区域，
            ## 模式数据区域及行数据区域中存储其相对于字符串数据区域开头的偏移量(4字节)
            ## 『COLUMN_TYPE_VLDATA』为二进制数据，其数据本身存储于字节数据区域，
            ## 模式数据区域及行数据区域中存储其相对于字节数据区域开头的偏移量(4字节)、数据长度(4字节)
            elif value_type == UTFTableValueType.COLUMN_TYPE_STRING:
                value_size = 4
                value_type_fc = ">I"
            elif value_type == UTFTableValueType.COLUMN_TYPE_VLDATA:
                value_size = 8
                value_type_fc = ">II"
            else:
                raise ValueError(f"unsupported value type: {value_type.name}")
            
            ## 获取列名
            if data_flag_name:
                column_name = self.stringDataGet(name_offset)

            ## 读取常量数据
            if data_flag_constant:
                if offset + value_size - 0x20 > self.schema_size:
                    raise ValueError(f"schema offset out of bounds: {offset + value_size - 0x20:#x}")
                stream.seek(offset)
                column_value = struct.unpack(value_type_fc, stream.read(value_size))
                offset += value_size

                ## 处理字符串以及二进制数据
                if value_type == UTFTableValueType.COLUMN_TYPE_STRING:
                    column_data_constant = self.stringDataGet(column_value[0])
                elif value_type == UTFTableValueType.COLUMN_TYPE_VLDATA:
                    column_data_constant = self.binaryDataGet(column_value[0], column_value[1])
                else:
                    column_data_constant = column_value[0]

            ## 获取行数据偏移量并逐行读取数据
            if data_flag_row:
                if offset_in_row + value_size > self.row_width:
                    raise ValueError(f"row offset out of bounds: {offset_in_row + value_size:#x}")
                column_offset_in_row = offset_in_row
                offset_in_row += value_size

                column_data_rows = []
                if value_type == UTFTableValueType.COLUMN_TYPE_STRING:
                    for row_idx in range(0, self.rows_count):
                        stream.seek(self.rows_offset + row_idx*self.row_width + column_offset_in_row)
                        column_row_value = struct.unpack(value_type_fc, stream.read(value_size))
                        column_data_rows.append(self.stringDataGet(column_row_value[0]))
                elif value_type == UTFTableValueType.COLUMN_TYPE_VLDATA:
                    for row_idx in range(0, self.rows_count):
                        stream.seek(self.rows_offset + row_idx*self.row_width + column_offset_in_row)
                        column_row_value = struct.unpack(value_type_fc, stream.read(value_size))
                        column_data_rows.append(self.binaryDataGet(column_row_value[0], column_row_value[1]))
                else:
                    for row_idx in range(0, self.rows_count):
                        stream.seek(self.rows_offset + row_idx*self.row_width + column_offset_in_row)
                        column_row_value = struct.unpack(value_type_fc, stream.read(value_size))
                        column_data_rows.append(column_row_value[0])

            ## 将此列的数据整理为字典
            column_data = {"dataFlag":data_flag, "valueType":value_type.name}

            if data_flag_name:
                column_data["columnName"] = column_name

            if data_flag_constant:
                column_data["columnDataConstant"] = column_data_constant

            if data_flag_row:
                column_data["columnDataRows"] = column_data_rows.copy()
            
            data_columns.append(column_data.copy())

        self.columns = data_columns
        self.parsed = True
            
    ## 将UTF表的数据整理为用于json输出的字典
    def utf2DictJson(self) -> dict:
        if not self.parsed:
            self.utfParse()

        if len(self.columns) != self.columns_count:
            raise ValueError(f"expected columns count {self.columns_count}, actual columns count {len(self.columns)}")
        
        data = {"tableName":self.table_name, "version":self.version, 
                "rowsCount":self.rows_count, "columnsCount":self.columns_count}
        
        data_columns = []
        for column in self.columns:
            data_column = column.copy()
            ## 将二进制数据编码为base64字符串
            if data_column["valueType"] == "COLUMN_TYPE_VLDATA":
                if data_column["dataFlag"] == 0x03:
                    data_column["columnDataConstant"] = base64.b64encode(data_column["columnDataConstant"]).decode(self.encoding)
                elif data_column["dataFlag"] == 0x05:
                    ## 生成新的列表存储行数据以避免影响原值
                    data_column_rows = [base64.b64encode(row).decode(self.encoding) for row in data_column["columnDataRows"]]
                    data_column["columnDataRows"] = data_column_rows
                elif data_column["dataFlag"] == 0x01:
                    pass
                else:
                    raise ValueError(f"unsupported data flag: {data_column["dataFlag"]}")
            data_columns.append(data_column)

        data["columns"] = data_columns

        return data
                    
    ## 将UTF表的数据递归地整理为用于json输出的字典
    ## UTF表可能以二进制数据的形式存储于另一张UTF表里，此处尝试将嵌套的所有UTF表整理为字典
    ## depth_max为最大深度，若当前深度大于此，则不再进行解析
    ## depth用于指示当前的深度，一般不会主动传入
    def utf2DictJsonRecursion(self, depth_max: int=5, depth: int=0) -> dict:
        if depth > depth_max:
            raise ValueError(f"current depth({depth}) exceeds the maximum depth({depth_max})")
        
        if not self.parsed:
            self.utfParse()

        if len(self.columns) != self.columns_count:
            raise ValueError(f"expected columns count {self.columns_count}, actual columns count {len(self.columns)}")
        
        data = {"tableName":self.table_name, "version":self.version, 
                "rowsCount":self.rows_count, "columnsCount":self.columns_count}
        
        data_columns = []
        for column in self.columns:
            data_column = column.copy()
            ## 将二进制数据编码为base64字符串
            if data_column["valueType"] == "COLUMN_TYPE_VLDATA":
                if data_column["dataFlag"] == 0x03:
                    data_raw = data_column["columnDataConstant"]
                    if (data_raw[:4] == b"@UTF") and (depth < depth_max):
                        data_column["valueType"] = "COLUMN_TYPE_VLDATA_UTFTABLE"
                        utf_table = UTFTable(data_raw)
                        utf_table_dict = utf_table.utf2DictJsonRecursion(depth_max, depth+1)
                        data_column["columnDataConstant"] = utf_table_dict.copy()
                    else:
                        data_column["columnDataConstant"] = base64.b64encode(data_raw).decode(self.encoding)
                elif data_column["dataFlag"] == 0x05:
                    ## 生成新的列表存储行数据以避免影响原值
                    ## 此处默认某列中的所有二进制数据都是UTF表(或者都不是)
                    data_raw = data_column["columnDataRows"][0]
                    if (data_raw[:4] == b"@UTF") and (depth < depth_max):
                        data_column["valueType"] = "COLUMN_TYPE_VLDATA_UTFTABLE"
                        data_column_rows = []
                        for row in data_column["columnDataRows"]:
                            utf_table = UTFTable(row)
                            utf_table_dict = utf_table.utf2DictJsonRecursion(depth_max, depth+1)
                            data_column_rows.append(utf_table_dict.copy())
                        data_column["columnDataRows"] = data_column_rows
                    else:
                        data_column_rows = [base64.b64encode(row).decode(self.encoding) for row in data_column["columnDataRows"]]
                        data_column["columnDataRows"] = data_column_rows
                elif data_column["dataFlag"] == 0x01:
                    pass
                else:
                    raise ValueError(f"unsupported data flag: {data_column["dataFlag"]}")
            data_columns.append(data_column)

        data["columns"] = data_columns

        return data
        
    ## 将UTF表的数据输出为json
    def jsonOutput(self, opt_path: str) -> None:
        with open(opt_path, "w", encoding=self.encoding) as file:
            json.dump(self.utf2DictJson(), file, ensure_ascii=False)

    def jsonOutputRecursion(self, opt_path: str) -> None:
        with open(opt_path, "w", encoding=self.encoding) as file:
            json.dump(self.utf2DictJsonRecursion(), file, ensure_ascii=False)


    ## 从字符串数据区域获取字符串，入参为其相对于字符串数据区域开头的偏移量
    def stringDataGet(self, offset: int) -> str:
        if offset >= self.strings_size:
            raise ValueError(f"strings offset out of bounds: {offset:#x}")
        stream = self.stream
        stream.seek(self.strings_offset + offset)
        strbytes = bytearray()
        strbyte = stream.read(1)
        while strbyte != b"\x00":
            strbytes += strbyte
            strbyte = stream.read(1)
        string = strbytes.decode(self.encoding)

        return string
    
    ## 从字节数据区域获取二进制数据，入参为其相对于字节数据区域开头的偏移量及数据大小
    def binaryDataGet(self, offset: int, size: int) -> bytes:
        if offset + size > self.data_size:
            raise ValueError(f"binary data offset out of bounds: {offset + size:#x}")
        stream = self.stream
        stream.seek(self.data_offset + offset)

        return stream.read(size)

    ## 输出文件头数据，调试用
    def headerDataOutput(self, opt_path: str) -> None:
        headerID = self.headerID.decode()
        header_data = {"headerID":headerID, "table_size":self.table_size, 
                       "version":self.version, "rows_offset":self.rows_offset, 
                       "strings_offset":self.strings_offset, "data_offset":self.data_offset, 
                       "name_offset_rtst":self.name_offset_rtst, "columns_count":self.columns_count, 
                       "row_width":self.row_width, "rows_count":self.rows_count
                       }
        
        with open(opt_path, "w", encoding="utf8") as file:
            json.dump(header_data, file, ensure_ascii=False, indent=4)

    ## 检查各列名称是否重复，并返回列名-列索引字典
    def checkColumnsName(self) -> dict[str, int]:
        columns_name = {}
        for idx in range(0, self.columns_count):
            column = self.columns[idx]
            if column["columnName"] not in columns_name:
                columns_name[column["columnName"]] = idx
            ## "Non"表示无效列???
            elif column["columnName"] == "Non":
                pass
            else:
                raise ValueError(f"duplicate column name: {column["columnName"]}")
            
        return columns_name
    
    ## 根据列名及行索引获取数据
    def getDataValue(self, column_name: str, row_idx: int):
        if "columns_names_dict" not in self.__dict__:
            self.columns_names_dict = self.checkColumnsName()

        if column_name not in self.columns_names_dict:
            raise ValueError(f"column not found: {column_name}")
        
        if (row_idx < 0) or (row_idx >= self.rows_count):
            raise ValueError(f"invalid row index: {row_idx}")
        
        column = self.columns[self.columns_names_dict[column_name]]
        if column["dataFlag"] == 0x01:
            return None
        elif column["dataFlag"] == 0x03:
            return column["columnDataConstant"]
        elif column["dataFlag"] == 0x05:
            return column["columnDataRows"][row_idx]
        else:
            raise ValueError(f"unsupported data flag: {column["dataFlag"]}")




class UTFTableBuilder:
    ## UTF表构建，核心传入参数为一个UTFTable实例，或者与UTFTable实例进行数据整理后所得的字典格式一致的数据字典或保存该字典的json文件路径
    ## 传入一个UTFTable实例时，会获取其table_name、version、rows_count、columns_count以及columns数据，以此为基础构建新的UTF表
    ## 传入一个字典或保存该字典的json文件路径时，会以此字典为基础构建新的UTF表
    ## UTFTableBuilder初始化后，在进行UTF表构建之前，可以对其中的数据进行修改

    ## encoding为构建UTF表时处理字符串所使用的编码，打开json文件时也会使用之
    ## offset_alignment为数据对齐偏移量，用于向字节数据区域写入数据时的对齐
    ## (aic的acb文件一般是以0x20为数据对齐偏移量进行对齐的，但实际上未经对齐处理的acb文件也能被正常读取)
    def __init__(self, data_raw: UTFTable | dict | str, encoding: str="utf8", offset_alignment: int | None = None) -> None:
        self.from_UTFTable = False
        self.encoding = encoding
        self.offset_alignment = offset_alignment
        if type(data_raw) == UTFTable:
            self.from_UTFTable = True
            if not data_raw.parsed:
                data_raw.utfParse()
            self.table_name = data_raw.table_name
            self.version = data_raw.version
            self.rows_count = data_raw.rows_count
            self.columns_count = data_raw.columns_count
            self.columns = copy.deepcopy(data_raw.columns)
        elif type(data_raw) == dict:
            self.data_raw_dict = data_raw
        elif type(data_raw) == str:
            with open(data_raw, "r", encoding=encoding) as file:
                self.data_raw_dict = json.load(file)
        else:
            raise ValueError(f"invalid data_raw type: {type(data_raw)}")
        
    ## UTF表构建
    ## 当以包含内嵌UTF表数据字典的字典为基础构建UTF表时，此方法会被递归地调用
    def build(self) -> bytes:
        if not self.from_UTFTable:
            self.dataDictExtract()

        ## 检查行数、列数是否合理
        if self.columns_count < 0:
            raise ValueError(f"invalid columns count: {self.columns_count}")
        if self.rows_count < 0:
            raise ValueError(f"invalid rows count: {self.rows_count}")
        if len(self.columns) != self.columns_count:
            raise ValueError(f"expected columns count {self.columns_count}, actual columns count {len(self.columns)}")
            
        ## 建立UTF表的头部区域、模式数据区域、行数据区域、字符串数据区域、字节数据区域
        header_data     = bytearray()
        schema_data     = bytearray()
        rows_data       = bytearray()
        strings_data    = bytearray()
        binary_data     = bytearray()

        ## 字符串数据区域偏移量字典，用于记录已有的字符串及其偏移量
        ## 当需要写入的字符串与已有的字符串相同时，则将已有字符串的偏移量写入对应数据区域，以避免存储重复的字符串
        strings_offset_dict = {}

        ## 根据行数建立各行数据
        rows_data_list = []
        for _ in range(0, self.rows_count):
            rows_data_list.append(bytearray())
            
        ## 写入表格名称
        table_name_offset = len(strings_data)
        strings_data = strings_data + self.table_name.encode(self.encoding) + b"\x00"

        ## 遍历各列，将数据写入对应的区域
        for column in self.columns:
            data_flag = column["dataFlag"]
            value_type = UTFTableValueType[column["valueType"]]
            type_flag = value_type.value

            ## 写入数据信息字节
            info = (data_flag << 4) + type_flag
            schema_data = schema_data + struct.pack(">B", info)

            ## 处理数据标志，同UTFTable类
            data_flag_name = False
            data_flag_constant = False
            data_flag_row = False
            if data_flag == 0x01:
                data_flag_name = True
            elif data_flag == 0x03:
                data_flag_name = True
                data_flag_constant = True
            elif data_flag == 0x05:
                data_flag_name = True
                data_flag_row = True
            else:
                raise ValueError(f"unsupported data flag: {data_flag}")
            
            ## 处理类型标志，同UTFTable类
            if value_type == UTFTableValueType.COLUMN_TYPE_UINT8:
                value_type_fc = ">B"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT8:
                value_type_fc = ">b"
            elif value_type == UTFTableValueType.COLUMN_TYPE_UINT16:
                value_type_fc = ">H"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT16:
                value_type_fc = ">h"
            elif value_type == UTFTableValueType.COLUMN_TYPE_UINT32:
                value_type_fc = ">I"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT32:
                value_type_fc = ">i"
            elif value_type == UTFTableValueType.COLUMN_TYPE_UINT64:
                value_type_fc = ">Q"
            elif value_type == UTFTableValueType.COLUMN_TYPE_SINT64:
                value_type_fc = ">q"
            elif value_type == UTFTableValueType.COLUMN_TYPE_FLOAT:
                value_type_fc = ">f"
            elif value_type == UTFTableValueType.COLUMN_TYPE_DOUBLE:
                value_type_fc = ">d"
            ## 注意，以下两种类型为变长类型，其在模式数据区域及行数据区域中仅存储起始偏移量等信息
            ## 『COLUMN_TYPE_STRING』为字符串，其数据本身存储于字符串数据区域，
            ## 模式数据区域及行数据区域中存储其相对于字符串数据区域开头的偏移量(4字节)
            ## 『COLUMN_TYPE_VLDATA』为二进制数据，其数据本身存储于字节数据区域，
            ## 模式数据区域及行数据区域中存储其相对于字节数据区域开头的偏移量(4字节)、数据长度(4字节)
            elif value_type == UTFTableValueType.COLUMN_TYPE_STRING:
                value_type_fc = ">I"
            elif value_type == UTFTableValueType.COLUMN_TYPE_VLDATA:
                value_type_fc = ">II"
            else:
                raise ValueError(f"unsupported value type: {value_type.name}")

            ## 写入列名数据
            if data_flag_name:
                column_name = column["columnName"]
                if column_name in strings_offset_dict:
                    column_name_offset = strings_offset_dict[column_name]
                else:
                    column_name_offset = len(strings_data)
                    strings_data = strings_data + column_name.encode(self.encoding) + b"\x00"
                    strings_offset_dict[column_name] = column_name_offset
                schema_data = schema_data + struct.pack(">I", column_name_offset)

            ## 写入常量数据
            if data_flag_constant:
                if value_type == UTFTableValueType.COLUMN_TYPE_STRING:
                    string = column["columnDataConstant"]
                    if string in strings_offset_dict:
                        string_offset = strings_offset_dict[string]
                    else:
                        string_offset = len(strings_data)
                        strings_data = strings_data + string.encode(self.encoding) + b"\x00"
                        strings_offset_dict[string] = string_offset
                    schema_data = schema_data + struct.pack(value_type_fc, string_offset)
                elif value_type == UTFTableValueType.COLUMN_TYPE_VLDATA:
                    bytes_raw = column["columnDataConstant"]
                    if self.offset_alignment is not None:
                        bytes_raw = self.bytearrayAlignmentProcess(bytes_raw)
                    bytes_offset = len(binary_data)
                    bytes_size = len(bytes_raw)
                    binary_data = binary_data + bytes_raw
                    schema_data = schema_data + struct.pack(value_type_fc, bytes_offset, bytes_size)
                else:
                    schema_data = schema_data + struct.pack(value_type_fc, column["columnDataConstant"])

            ## 写入行数据
            if data_flag_row:
                ## 检查行数据列表长度与预期行数是否一致
                rows = column["columnDataRows"]
                if len(rows) != self.rows_count:
                    raise ValueError(f"expected rows count {self.rows_count}, actual rows count {len(rows)}")
                if value_type == UTFTableValueType.COLUMN_TYPE_STRING:
                    for idx in range(0, self.rows_count):
                        string = rows[idx]
                        if string in strings_offset_dict:
                            string_offset = strings_offset_dict[string]
                        else:
                            string_offset = len(strings_data)
                            strings_data = strings_data + string.encode(self.encoding) + b"\x00"
                            strings_offset_dict[string] = string_offset
                        rows_data_list[idx] = rows_data_list[idx] + struct.pack(value_type_fc, string_offset)
                elif value_type == UTFTableValueType.COLUMN_TYPE_VLDATA:
                    for idx in range(0, self.rows_count):
                        bytes_raw = rows[idx]
                        if self.offset_alignment is not None:
                            bytes_raw = self.bytearrayAlignmentProcess(bytes_raw)
                        bytes_offset = len(binary_data)
                        bytes_size = len(bytes_raw)
                        binary_data = binary_data + bytes_raw
                        rows_data_list[idx] = rows_data_list[idx] + struct.pack(value_type_fc, bytes_offset, bytes_size)
                else:
                    for idx in range(0, self.rows_count):
                        rows_data_list[idx] = rows_data_list[idx] + struct.pack(value_type_fc, rows[idx])

        ## 检查各行长度是否一致
        row_width = 0
        if self.rows_count > 0:
            row_width = len(rows_data_list[0])
            if any((len(row) != row_width) for row in rows_data_list):
                raise ValueError(f"lengths of each rows are not entirely consistent")
            ## 将各行数据写入行数据区域
            for row in rows_data_list:
                rows_data = rows_data + row
            
        ## 计算各区域大小及其偏移量
        schema_size         = len(schema_data)
        rows_size           = len(rows_data)
        strings_size        = len(strings_data)
        binary_data_size    = len(binary_data)

        rows_offset         = 0x20 + schema_size
        strings_offset      = rows_offset + rows_size
        binary_data_offset  = strings_offset + strings_size
        table_size          = binary_data_offset + binary_data_size

        ## 处理数据对齐并更新相关数据
        if self.offset_alignment is not None:
            remainder = binary_data_offset % self.offset_alignment
            if remainder > 0:
                strings_data = strings_data + bytearray(self.offset_alignment - remainder)
                strings_size        = len(strings_data)
                binary_data_offset  = strings_offset + strings_size
                table_size          = binary_data_offset + binary_data_size

        ## 写入文件头部数据
        header_data += b"@UTF"
        header_data += struct.pack(">I", table_size - 0x08)
        header_data += struct.pack(">H", self.version)
        header_data += struct.pack(">H", rows_offset - 0x08)
        header_data += struct.pack(">I", strings_offset - 0x08)
        header_data += struct.pack(">I", binary_data_offset - 0x08)
        header_data += struct.pack(">I", table_name_offset)
        header_data += struct.pack(">H", self.columns_count)
        header_data += struct.pack(">H", row_width)
        header_data += struct.pack(">I", self.rows_count)

        ## 拼接各区域数据并输出
        data_result = header_data + schema_data + rows_data + strings_data + binary_data
        return bytes(data_result)

    ## 从UTF表数据字典中提取数据
    ## 当UTF表数据字典中含有内嵌的UTF表数据字典时，此方法会被递归地调用
    def dataDictExtract(self) -> None:
        self.table_name = self.data_raw_dict["tableName"]
        self.version = self.data_raw_dict["version"]
        self.rows_count = self.data_raw_dict["rowsCount"]
        self.columns_count = self.data_raw_dict["columnsCount"]

        data_columns = []
        for column_raw in self.data_raw_dict["columns"]:
            column_data = {}
            column_data["dataFlag"] = column_raw["dataFlag"]
            column_data["valueType"] = column_raw["valueType"]

            ## 读取各列数据，将其中以base64字符串存储的二进制数据还原为字节串
            ## 若所存储的数据为内嵌的UTF表数据字典，则将其构建为原始的二进制形式的UTF表
            if column_raw["dataFlag"] == 0x01:
                column_data["columnName"] = column_raw["columnName"]
            ## 处理常量数据
            elif column_raw["dataFlag"] == 0x03:
                column_data["columnName"] = column_raw["columnName"]
                if column_raw["valueType"] == "COLUMN_TYPE_VLDATA":
                    column_data["columnDataConstant"] = base64.b64decode(column_raw["columnDataConstant"])
                elif column_raw["valueType"] == "COLUMN_TYPE_VLDATA_UTFTABLE":
                    utf_builder = UTFTableBuilder(column_raw["columnDataConstant"], self.encoding, self.offset_alignment)
                    column_data["columnDataConstant"] = utf_builder.build()
                    column_data["valueType"] = "COLUMN_TYPE_VLDATA"
                elif column_raw["valueType"] in UTFTableValueType.__members__:
                    column_data["columnDataConstant"] = column_raw["columnDataConstant"]
                else:
                    raise ValueError(f"unsupported value type: {column_raw["valueType"]}")
            ## 处理行数据
            ## 生成新的列表存储行数据以避免影响原值
            elif column_raw["dataFlag"] == 0x05:
                column_data["columnName"] = column_raw["columnName"]
                if column_raw["valueType"] == "COLUMN_TYPE_VLDATA":
                    column_data_rows = [base64.b64decode(row) for row in column_raw["columnDataRows"]]
                    column_data["columnDataRows"] = column_data_rows
                elif column_raw["valueType"] == "COLUMN_TYPE_VLDATA_UTFTABLE":
                    column_data_rows = []
                    for row in column_raw["columnDataRows"]:
                        utf_builder = UTFTableBuilder(row, self.encoding, self.offset_alignment)
                        column_data_rows.append(utf_builder.build())
                    column_data["columnDataRows"] = column_data_rows
                    column_data["valueType"] = "COLUMN_TYPE_VLDATA"
                elif column_raw["valueType"] in UTFTableValueType.__members__:
                    column_data["columnDataRows"] = column_raw["columnDataRows"].copy()
                else:
                    raise ValueError(f"unsupported value type: {column_raw["valueType"]}")
            else:
                raise ValueError(f"unsupported data flag: {column_raw["dataFlag"]}")
            
            data_columns.append(column_data.copy())

        self.columns = data_columns

    ## 构建UTF表并输出至指定文件
    def buildFile(self, opt_path: str) -> None:
        with open(opt_path, "wb") as file:
            file.write(self.build())

    ## 数据对齐处理，若不足则于原数据后填充`00`字节
    def bytearrayAlignmentProcess(self, bytes_raw: Buffer) -> bytes:
        bytes_result = bytearray()
        bytes_raw_size = len(bytes_raw)
        remainder = bytes_raw_size % self.offset_alignment
        if remainder > 0:
            bytes_result = bytes_raw + bytearray(self.offset_alignment - remainder)
        else:
            ## remainder == 0
            bytes_result = bytes_raw
        return bytes(bytes_result)


