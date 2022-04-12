import argparse

'''
Dex file format:
 1. File Header
 2. String Table
 3. Class List
 4. Field Table
 5. Method Table
 6. Class Definition Table
 7. Field List
 8. Method List
 9. Code Header
 10. Local Variable List
'''

gTypeDescriptor = {
    b'V':b'void',
    b'Z':b'boolean',
    b'B':b'byte',
    b'S':b'short',
    b'C':b'char',
    b'I':b'int',
    b'J':b'long',
    b'F':b'float',
    b'D':b'double'
}

gAccessFlag = {
    0x1:b'ACC_PUBLIC',
    0x2:b'ACC_PRIVATE',
    0x4:b'ACC_PROTECTED',
    0x8:b'ACC_STATIC',
    0x10:b'ACC_FINAL',
    0x20:b'ACC_SYNCHRONIZED',
    0x40:b'ACC_VOLATILE',
    0x40:b'ACC_BRIDGE',
    0x80:b'ACC_TRANSIENT',
    0x80:b'ACC_VARARGS',
    0x100:b'ACC_NATIVE',
    0x200:b'ACC_INTERFACE',
    0x400:b'ACC_ABSTRACT',
    0x800:b'ACC_STRICT',
    0x1000:b'ACC_SYNTHETIC',
    0x2000:b'ACC_ANNOTATION',
    0x4000:b'ACC_ENUM',	
    0x8000:b'acc_no_use',	 	 	 
    0x10000:b'ACC_CONSTRUCTOR',
    0x20000:b'ACC_DECLARED_SYNCHRONIZED',
}

gMapTypeCode = {
    0x0000:b'kDexTypeHeaderItem',               
    0x0001:b'kDexTypeStringIdItem',             
    0x0002:b'kDexTypeTypeIdItem',               
    0x0003:b'kDexTypeProtoIdItem',              
    0x0004:b'kDexTypeFieldIdItem',              
    0x0005:b'kDexTypeMethodIdItem',             
    0x0006:b'kDexTypeClassDefItem',             
    0x1000:b'kDexTypeMapList',                  
    0x1001:b'kDexTypeTypeList',                 
    0x1002:b'kDexTypeAnnotationSetRefList',     
    0x1003:b'kDexTypeAnnotationSetItem',        
    0x2000:b'kDexTypeClassDataItem',            
    0x2001:b'kDexTypeCodeItem',                 
    0x2002:b'kDexTypeStringDataItem',           
    0x2003:b'kDexTypeDebugInfoItem',            
    0x2004:b'kDexTypeAnnotationItem',           
    0x2005:b'kDexTypeEncodedArrayItem',         
    0x2006:b'kDexTypeAnnotationsDirectoryItem', 
}



def printl(mylist:list):
    for i in mylist:
        print(i)

class DexFile:
    def __init__(self, dex_bytes) -> None:
        self.dex_bytes = dex_bytes
    def le(self, start, size):
        return int.from_bytes(self.dex_bytes[start:start+size], 'little')
    def be(self, start, size):
        return int.from_bytes(self.dex_bytes[start:start+size], 'big')
    def dd(self, start, size):
        return self.dex_bytes[start:start+size]
    def uleb128(self, uleb128_bytes):
        # uleb128 = lambda pos : int.from_bytes(uleb128_bytes[pos],'little') 
        pt   = 0
        res  = uleb128_bytes[pt] & 0x7F
        data = uleb128_bytes[pt]
        while( data > 0x7F and pt < 4):
            pt   += 1
            data = uleb128_bytes[pt]
            res  = res | ((data&0x7F) << (7*pt))
        return res,pt
    def true_type(self,type_bytes):
        if type_bytes in gTypeDescriptor:
            return gTypeDescriptor[type_bytes]
        elif type_bytes[0:1] == b'[':
            res = b''
            i = 0
            while(type_bytes[i:i+1] == b'['):
                res += b'[]'
                i += 1
            return self.true_type(type_bytes[i:]) + res
        elif type_bytes[0:1] == b'L':
            return type_bytes[1:-1]
    def re_access_flag(flag:int)->bytes:
        # TODO 
        pass


class MyDex(DexFile):
    def __init__(self, dex_bytes) -> None:
        super().__init__(dex_bytes)
        self.dex_bytes = dex_bytes
        dex_header = self.dex_header = DexHeader(dex_bytes)

        self.link_size       = dex_header.link_size      
        self.link_off        = dex_header.link_off       
        self.map_off         = dex_header.map_off        
        self.string_ids_size = dex_header.string_ids_size
        self.string_ids_off  = dex_header.string_ids_off 
        self.type_ids_size   = dex_header.type_ids_size  
        self.type_ids_off    = dex_header.type_ids_off   
        self.proto_ids_size  = dex_header.proto_ids_size 
        self.proto_ids_off   = dex_header.proto_ids_off  
        self.field_ids_size  = dex_header.field_ids_size 
        self.field_ids_off   = dex_header.field_ids_off  
        self.method_ids_size = dex_header.method_ids_size
        self.method_ids_off  = dex_header.method_ids_off 
        self.class_defs_size = dex_header.class_defs_size
        self.class_defs_off  = dex_header.class_defs_off 
        self.data_size       = dex_header.data_size      
        self.data_off        = dex_header.data_off

        self.dex_string_ids = DexStringIds(dex_bytes, self.string_ids_off, self.string_ids_size)
        self.dex_type_ids   = DexTypeIds  (dex_bytes, self.type_ids_off  , self.type_ids_size , self.dex_string_ids.string_list)
        self.dex_proto_ids  = DexProtoIds (dex_bytes, self.proto_ids_off , self.proto_ids_size, self.dex_string_ids.string_list, self.dex_type_ids.type_list)
        self.dex_field_ids  = DexFieldIds (dex_bytes, self.field_ids_off , self.field_ids_size, self.dex_string_ids.string_list, self.dex_type_ids.type_list)
        self.dex_method_ids = DexMethodIds(dex_bytes, self.method_ids_off, self.method_ids_size,self.dex_string_ids.string_list, self.dex_type_ids.type_list, self.dex_proto_ids.proto_meaning)
        self.dex_class_refs = DexClassDefs(dex_bytes, self.class_defs_off, self.class_defs_size,self.dex_string_ids.string_list, self.dex_type_ids.type_list)
        self.dex_map_list   = DexMapList  (dex_bytes, self.map_off)



    def show_me(self):
        pass

class DexHeader(MyDex):
    def __init__(self, dex_bytes) -> None:
        self.dex_bytes = dex_bytes
        
        self.magic           = self.dd(0x0, 0x8)
        self.checksum        = self.le(0x8, 0x4)    # Alder32 checksum
        self.signature       = self.be(0xC,0x14)    # SHA-1 signature
        self.file_size       = self.le(0x20,0x4)    # entire file
        self.header_size     = self.le(0x24,0x4)    # off to start of next section
        self.endian_tag      = self.dd(0x28,0x4)
        self.link_size       = self.le(0x2C,0x4)
        self.link_off        = self.le(0x30,0x4)
        self.map_off         = self.le(0x34,0x4)
        self.string_ids_size = self.le(0x38,0x4)
        self.string_ids_off  = self.le(0x3C,0x4)
        self.type_ids_size   = self.le(0x40,0x4)
        self.type_ids_off    = self.le(0x44,0x4)
        self.proto_ids_size  = self.le(0x48,0x4)
        self.proto_ids_off   = self.le(0x4C,0x4)
        self.field_ids_size  = self.le(0x50,0x4)
        self.field_ids_off   = self.le(0x54,0x4)
        self.method_ids_size = self.le(0x58,0x4)
        self.method_ids_off  = self.le(0x5C,0x4)
        self.class_defs_size = self.le(0x60,0x4)
        self.class_defs_off  = self.le(0x64,0x4)
        self.data_size       = self.le(0x68,0x4)
        self.data_off        = self.le(0x6C,0x4)

    def show_me(self):
        print('-'*0x50+'\n'+'DexHeader'.ljust(0x28+len('DexHeader')//2,'*').rjust(0x50,'*')+'\n'+'-'*0x50)
        print('magic:'.ljust(18, ' '),self.magic)
        print('checksum:'.ljust(18, ' '),self.checksum)
        print('signature:'.ljust(18, ' '),self.signature)
        print('file_size:'.ljust(18, ' '),self.file_size)
        print('header_size:'.ljust(18, ' '),self.header_size)
        print('endian_tag:'.ljust(18, ' '),self.endian_tag)
        print('link_size:'.ljust(18, ' '),self.link_size)
        print('link_off:'.ljust(18, ' '),self.link_off)
        print('map_off:'.ljust(18, ' '),self.map_off)
        print('string_ids_size:'.ljust(18, ' '),self.string_ids_size)
        print('string_ids_off:'.ljust(18, ' '),self.string_ids_off)
        print('type_ids_size:'.ljust(18, ' '),self.type_ids_size)
        print('type_ids_off:'.ljust(18, ' '),self.type_ids_off)
        print('proto_ids_size:'.ljust(18, ' '),self.proto_ids_size)
        print('proto_ids_off:'.ljust(18, ' '),self.proto_ids_off)
        print('field_ids_size:'.ljust(18, ' '),self.field_ids_size)
        print('field_ids_off:'.ljust(18, ' '),self.field_ids_off)
        print('method_ids_size:'.ljust(18, ' '),self.method_ids_size)
        print('method_ids_off:'.ljust(18, ' '),self.method_ids_off)
        print('class_defs_size:'.ljust(18, ' '),self.class_defs_size)
        print('class_defs_off:'.ljust(18, ' '),self.class_defs_off)
        print('data_size:'.ljust(18, ' '),self.data_size)
        print('data_off:'.ljust(18, ' '),self.data_off)

    

class DexStringIds(MyDex):
    def __init__(self, dex_bytes, off, size) -> None:
        self.dex_bytes = dex_bytes[off: off+size*4]
        self.string_off_list = [self.le(0x4*i , 0x4) for i in range(size)]
        self.string_list = []
        for i in self.string_off_list:
            string_size, pt = self.uleb128(dex_bytes[i:i+5])
            self.string_list.append(dex_bytes[i+1+pt:i+1+pt+string_size])
    
    def show_me(self):
        print('-'*0x50+'\n'+'DexStringIds->DexString'.ljust(0x28+len('DexStringIds->DexString')//2,'*').rjust(0x50,'*')+'\n'+'-'*0x50)
        printl(self.string_list)



class DexTypeIds(MyDex):
    def __init__(self, dex_bytes, off, size, string_list) -> None:
        self.dex_bytes = dex_bytes[off: off+size*4]
        self.type_off_list = [self.le(0x4*i , 0x4) for i in range(size)]
        self.type_list = []
        for i in self.type_off_list:
            self.type_list.append(string_list[i])

    def show_me(self):
        print('-'*0x50+'\n'+'DexTypeIds->DexType'.ljust(0x28+len('DexTypeIds->DexType')//2,'*').rjust(0x50,'*')+'\n'+'-'*0x50)
        printl(self.type_list)
        
class DexProtoIds(MyDex):
    '''
    Java Arch Method
    '''
    def __init__(self, dex_bytes, off, size, string_list, type_list) -> None:
        gle = lambda off, size : int.from_bytes(dex_bytes[off:off+size], 'little') 
        self.dex_bytes = dex_bytes[off: off+size*12]
        self.proto_list_data = [self.dd(0xC*i, 0xC) for i in range(size)]
        self.proto_list = []
        self.proto_meaning = []
        meaning = ''
        for i in range(size):
            shorty_idx      = self.le(0xC*i, 0x4)
            return_type_idx = self.le(0xC*i+0x4, 0x4)
            parameters_off  = self.le(0xC*i+0x8, 0x4)
            if parameters_off == 0:
                meaning = self.true_type(type_list[return_type_idx]).decode('utf8') + ' fun' + str(i) + '( )'
                self.proto_list.append((string_list[shorty_idx],type_list[return_type_idx]))
            else:
                meaning = self.true_type(type_list[return_type_idx]).decode('utf8') + ' fun' + str(i) + '('
                param_size = gle(parameters_off, 0x4)
                param = []
                for j in range(param_size):
                    my_type = type_list[gle(parameters_off + 4 + 0x2*j, 0x2)]
                    meaning += self.true_type(my_type).decode('utf8') + ','
                    param.append(my_type)
                meaning += ')'
                self.proto_list.append((string_list[shorty_idx], type_list[return_type_idx], param))

            self.proto_meaning.append(meaning)
            
    def show_me(self):
        print('-'*0x50+'\n'+'DexProto'.ljust(0x28+len('DexProto')//2,'*').rjust(0x50,'*')+'\n'+'-'*0x50)
        printl(self.proto_meaning)

class DexFieldIds(MyDex):
    '''
    Java Class
    '''
    def __init__(self, dex_bytes, off, size, string_list, type_list) -> None:
        self.dex_bytes = dex_bytes[off: off+size*8]
        self.field_list = []
        self.field_meaning = []
        meaning = ''
        for i in range(size):
            class_idx = self.le(0x8*i    , 0x2)
            type_idx  = self.le(0x8*i+0x2, 0x2)
            name_idx  = self.le(0x8*i+0x4, 0x4)
            self.field_list.append((self.true_type(type_list[class_idx]), self.true_type(type_list[type_idx]), string_list[name_idx]))

    def show_me(self):
        print('-'*0x50+'\n'+'DexField'.ljust(0x28+len('DexField')//2,'*').rjust(0x50,'*')+'\n'+'-'*0x50)
        printl(self.field_list)

class DexMethodIds(MyDex):
    '''
    Method
    '''
    def __init__(self, dex_bytes, off, size, string_list, type_list, proto_list) -> None:
        self.dex_bytes = dex_bytes[off: off + 0x8*size]
        method_class_idx_list = [self.le(0x8*i, 0x2) for i in range(size)]
        method_proto_idx_list = [self.le(0x8*i+0x2, 0x2) for i in range(size)]
        method_name_idx_list = [self.le(0x8*i+0x4, 0x4) for i in range(size)]
        self.method_list = []
        self.method_meaning = []
        for i in range(size):
            self.method_list.append((self.true_type(type_list[method_class_idx_list[i]])
                                    ,proto_list[method_proto_idx_list[i]]
                                    ,string_list[method_name_idx_list[i]]))
                    
    def show_me(self):
        print('-'*0x50+'\n'+'DexMethod'.ljust(0x28+len('DexMethod')//2,'*').rjust(0x50,'*'))
        print('          Class Type        Declear Type        Method Name'.ljust(0x50,' '))
        print('-'*0x50)
        printl(self.method_list)

class DexClassDefs(MyDex):
    def __init__(self, dex_bytes, off, size, string_list, type_list) -> None:
        gle = lambda off, size : int.from_bytes(dex_bytes[off:off+size], 'little') 
        self.dex_bytes = dex_bytes[off: off + 0x20*size]
        class_idx       = [self.le(0x20*i, 0x4) for i in range(size)]
        access_flags    = [self.dd(0x20*i+0x4, 0x4) for i in range(size)]
        super_class_idx = [self.le(0x20*i+0x8, 0x4) for i in range(size)]
        interfaces_off  = [self.le(0x20*i+0xC, 0x4) for i in range(size)]
        source_file_idx = [self.le(0x20*i+0x10, 0x4) for i in range(size)]
        annotations_off = [self.le(0x20*i+0x14, 0x4) for i in range(size)]
        class_data_off  = [self.le(0x20*i+0x18, 0x4) for i in range(size)]
        static_value_off= [self.le(0x20*i+0x1C, 0x4) for i in range(size)]
        self.class_refs = []
        for i in range(size):
            if interfaces_off[i] != 0:
                interfaces_size = gle(interfaces_off[i], 0x4)
                interfaces_off[i] = [self.true_type(type_list[gle(interfaces_off[i]+0x2*j, 0x2)]) for j in range(interfaces_size)]
            self.class_refs.append((self.true_type(type_list[class_idx[i]]),
                                    access_flags[i],
                                    self.true_type(type_list[super_class_idx[i]]),
                                    interfaces_off[i],
                                    string_list[source_file_idx[i]],
                                    annotations_off[i],
                                    class_data_off[i],
                                    static_value_off[i] ))

    def show_me(self):
        print('-'*0x50+'\n'+'DexClass'.ljust(0x28+len('DexClass')//2,'*').rjust(0x50,'*'))
        print('Class Type|AccessFlags|Superclass|interfaces|sourceFile|annotationOff|classDataOff|staticValueOff'.ljust(0x50, ' '))
        print('-'*0x50)
        printl(self.class_refs)

class DexMapList(MyDex):
    def __init__(self, dex_bytes, off) -> None:
        self.dex_bytes = dex_bytes[off:]
        map_size = self.le(0, 0x4)
        map_type_list   = [self.le(0xC*i+0x4, 0x2) for i in range(map_size)]
        map_unused_list = [self.le(0xC*i+0x4+0x2, 0x2) for i in range(map_size)]
        map_size_list   = [self.le(0xC*i+0x4+0x4, 0x4) for i in range(map_size)]
        map_offset_list = [self.le(0xC*i+0x4+0x8, 0x4) for i in range(map_size)]
        self.map_list = []
        for i in range(map_size):
            self.map_list.append((gMapTypeCode[map_type_list[i]],
                                  map_unused_list[i],
                                  map_size_list[i],
                                  map_offset_list[i]))
        
    def show_me(self):
        print('-'*0x50+'\n'+'DexMap'.ljust(0x28+len('DexMap')//2,'*').rjust(0x50,'*'))
        print('     TYPE_CODES     unused     size      offset'.ljust(0x50,' '))
        print('-'*0x50)
        printl(self.map_list)


if __name__ == '__main__':
    args = argparse.ArgumentParser(description = 'purpose: analyze dex',epilog = 'information end')
    args.add_argument('-i', type=str, dest='dex_path'  , help='input file path')
    args.add_argument('--all', action='store_true', dest='all' , help='show all')
    args.add_argument('--header', action='store_true', dest='header', help='show header')
    args.add_argument('--string', action='store_true', dest='string', help='show string')
    args.add_argument('--type', action='store_true', dest='type', help='show type')
    args.add_argument('--proto', action='store_true', dest='proto', help='show proto')
    args.add_argument('--field', action='store_true', dest='field', help='show field')
    args.add_argument('--method', action='store_true', dest='method', help='show method')
    args.add_argument('--class', action='store_true', dest='class', help='show class')
    args.add_argument('--map', action='store_true', dest='map', help='show map')
    
    args = args.parse_args()
    if not vars(args)['dex_path']:
        print('Plz Input Dex Path')
        exit(1)

    with open(vars(args)['dex_path'], 'rb') as f:
        data = f.read()
        dex = MyDex(data)
        if vars(args)['all']:
            dex.dex_header.show_me()
            dex.dex_string_ids.show_me()
            dex.dex_type_ids.show_me()
            dex.dex_proto_ids.show_me()
            dex.dex_field_ids.show_me()
            dex.dex_method_ids.show_me()
            dex.dex_class_refs.show_me()
            dex.dex_map_list.show_me()
        else:
            if vars(args)['header']:
                dex.dex_header.show_me()
            if vars(args)['string']:
                dex.dex_string_ids.show_me()
            if vars(args)['type']:
                dex.dex_type_ids.show_me()
            if vars(args)['proto']:
                dex.dex_proto_ids.show_me()
            if vars(args)['field']:
                dex.dex_field_ids.show_me()
            if vars(args)['method']:
                dex.dex_method_ids.show_me()
            if vars(args)['class']:
                dex.dex_class_refs.show_me()
            if vars(args)['map']:
                dex.dex_map_list.show_me()
        