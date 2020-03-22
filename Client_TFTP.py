import enum
import sys
import os
import socket
import struct
import sys
import socket

from enum import Enum
class TftpProcessor(object):


    class TftpPacketType(enum.Enum):
      
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):

        self.packet_buffer = []
        self.operation = None
        self.filename = None
        pass

    def process_udp_packet(self, packet_data, packet_source):

        print(f"Received a packet from {packet_source}")
        # in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(packet_data)

        struct_=(out_packet[1],out_packet[2])
        self.packet_buffer.append(out_packet[0])
        if len(out_packet[3]) < 512:
            self.operation = None
        with open(self.filename, "a+") as f:
            f.write(out_packet[3])
        return struct_
        
    def _DATA_parse(self,requestByteArray):
        temp = struct.unpack("!H", requestByteArray[:2])
        opcode = temp[0]
        x = requestByteArray[4:]
        data = x.decode("ascii")
        bn = struct.unpack("!H", requestByteArray[2:4])[0]
        return opcode, data, bn


    def _Ack_parse(self,requestByteArray):
        bn = requestByteArray[2]
        return bn



    def _parse_udp_packet(self, packet_bytes):
        opcode = struct.unpack("!H", packet_bytes[:2])[0]
        if opcode ==3:
            _OP, data_, bn_ =self._DATA_parse(packet_bytes)
            return _OP
        elif opcode ==4:
            bn_ = self._Ack_parse(packet_bytes)
            return opcode
        else :
            return "ERROR"

    def _do_some_logic(self, input_packet):
        _OP, data_, _Block_Number =self._DATA_parse(input_packet)
        return (struct.pack('!HH', 4, _Block_Number), _OP, _Block_Number, data_)


    def get_next_output_packet(self):
        _The_Top=self.packet_buffer.pop(0)
        return _The_Top

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def read_theChuncked_File(self, file_name,_Flag):
        with open (file_name,'rb') as f:
        
            while True :
                chunkinBlockSize=f.read(512)
            if not chunkinBlockSize:
               print("File not accessible")
            else :
                _Flag=1+_Flag
                file_s=struct.pack('>h{}sB{}sB',3,int(_Flag),chunkinBlockSize)
                self.packet_buffer.append(file_s)

    def request_file(self, file_path_on_server):
        # Request File == RRQ Build
        self.operation = 'pull'
        mode = "octet"
        request = bytearray()
        opcode_RRQ = bytearray()
        opcode_RRQ.append(0)
        opcode_RRQ.append(1)
        filename = bytearray(file_path_on_server.encode('utf-8'))
        request += filename
        the_null_terminator = 0
        request.append(the_null_terminator)
        form = bytearray(bytes(mode, 'utf-8'))
        request += form
        last_byte = 0
        request.append(last_byte)
        opcode_RRQ.extend(request)
        print("RRQ...")
        return self.packet_buffer.append(opcode_RRQ)


    def upload_file(self, file_path_on_server):
        mode = "octet"
        request = bytearray()
        opcode_WRQ = bytearray()
        opcode_WRQ.append(0)
        opcode_WRQ.append(2)
        filename = bytearray(file_path_on_server.encode('utf-8'))
        request += filename
        the_null_terminator = 0
        request.append(the_null_terminator)
        form = bytearray(bytes(mode, 'utf-8'))
        request += form
        last_byte = 0
        request.append(last_byte)
        opcode_WRQ.extend(request)
        print("WRQ...")
        return self.packet_buffer.append(opcode_WRQ)


    def execute_socket_(self,server_address,client_socket):
        the_TOP=self.get_next_output_packet()#Our Data
        client_socket.sendto(the_TOP, server_address)
        if self.operation:
            _Response = client_socket.recvfrom(516)
        else:
            exit()
        return _Response

    def _Execute_Download(self,file_path_on_server,recieved_data_New,address_New,client_socket,address):
        f=open(file_path_on_server,'rb')
        op, data_, bn_ =self._DATA_parse(recieved_data_New)
        downLoading_=0
        while len(recieved_data_New)!=516:
              if op==3:
                 the_TOP=self.get_next_output_packet()#Our Data
                 f.write(the_TOP)
                 fileD=struct.pack("!hh",4,bn_)
                 self.packet_buffer.append(fileD)
                 recieved_data, address =self.execute_socket_(client_socket, address)
                 downLoading_+=1
                 print("downLoading done")

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass







def block_is_sent(retrans_counter ,next_Index,operation):
    if operation=="push":#Upload
       if retrans_counter [0]==4 and retrans_counter [1]==int(next_Index+1):
          print("Next block is sent..")
       else:
          print('error')









def parse_user_input(address, operation, file_name=None):
    print(f"Attempting to upload [{file_name}]...")

    object_Processor=TftpProcessor()
    object_Processor.filename = file_name
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if operation == "push":
        next_Packet=0

        byte_data_file=object_Processor.upload_file(file_name)
        object_Processor.read_theChuncked_File(file_name,next_Packet)
        the_RESPONSE=object_Processor.execute_socket_(address,client_socket)
        recieved_data,address=the_RESPONSE[0],the_RESPONSE[1]
        struct_Upload=object_Processor.process_udp_packet(recieved_data,address)
        op_,block_Number=struct_Upload[0],struct_Upload[1]
        while (object_Processor.has_pending_packets_to_be_sent()):
            the_RESPONSE_New=object_Processor.execute_socket_(address,client_socket)
            recieved_data_New,address_New=the_RESPONSE_New[0],the_RESPONSE_New[1]
            struct_Upload_new=object_Processor.process_udp_packet(recieved_data_New,address_New)
            block_is_sent(struct_Upload_new,next_Packet, operation)
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        byte_data_file=object_Processor.request_file(file_name)
        the_RESPONSE=object_Processor.execute_socket_(address,client_socket)
        recieved_data,address=the_RESPONSE[0],the_RESPONSE[1]
        struct_Upload=object_Processor.process_udp_packet(recieved_data,address)
        op_,block_Number=struct_Upload[0],struct_Upload[1]
        next_Packet=0
        while (object_Processor.has_pending_packets_to_be_sent()):
            the_RESPONSE_New=object_Processor.execute_socket_(address,client_socket)
            recieved_data_New,address_New=the_RESPONSE_New[0],the_RESPONSE_New[1]
            struct_Upload_new=object_Processor.process_udp_packet(recieved_data_New,address_New)
            object_Processor._Execute_Download(file_name,recieved_data_New,address_New,client_socket,address)

def get_arg(param_index, default=None):

    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input((ip_address, 69), operation, file_name)


if __name__ == "__main__":
    main()
