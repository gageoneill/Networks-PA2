import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10

    ## length of md5 checksum in hex
    checksum_length = 32 

    # Acknowledgment and negative Acknowledgment length
    ack_nak_length = 1
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
    
    # Packet should handle ACK and NAK flags
    # basically init method should be changed

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')

        #extract the fields
        # slice the byte_S[ 0: (10 + sequence number) ]
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length + Packet.seq_num_S_length])

        # slice the byte_S[ (10 + sequence number + checksum_length) : last index ]
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length :]

        #[TEST]
        print("\n==================================================================================")
        print("\tDebugging Packet")
        print("\tPacket: from_byte_S(self, byte_S):")
        print("\t\tPacket: # %s" % (seq_num) )
        print("\t\tseq_num: %s" % (seq_num) )
        print("\t\tmsg_S: %s" % (msg_S) )
        print("\t\tbyte_S: %s" % (byte_S) )
        print("==================================================================================\n")

        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        
        # Note
        # ============================================================= #
        # The method zfill() pads string on the left with zeros to fill width.
        # width - width of the string
        #length_S = str().zfill(width); 

        # TEST
        #demo_length = 4
        #demo_str = ''.zfill(demo_length)
        # out-put is 0000
        # ============================================================= #

        # The packet length: convert length to a byte field of length_S_length bytes
        packet_length = self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)

        # fill in the byte field with the packet_length
        length_S = str(packet_length).zfill(self.length_S_length)
        
        #compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()

        #[TEST]
        print("\n==================================================================================")
        print("\tDebugging Packet")
        print("\tPacket: get_byte_S(self):")
        print("\t\tPacket: # %d" % (self.seq_num) )
        print("\t\tpacket_length: %d" % (packet_length) )
        print("\t\tseq_num_S: " + seq_num_S)
        print("\t\tlength_S: " + length_S)
        print("\t\tchecksum_S: " + checksum_S)
        print("\t\tmsg_S: " + self.msg_S)
        print("\t\treturn string or packet: %s" % (length_S + seq_num_S + checksum_S + self.msg_S) )
        print("\t\tFinal packet Len: %d" % (  len(length_S + seq_num_S + checksum_S + self.msg_S) ) )
        print("==================================================================================\n")

        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):

        # Note
        # =================================================================================== #
        # Slicing an Array: Python has a slicing feature which allows to access pieces of an array. We, basically,
        # slice an array using a given range (eg. X to Y position [including X and Y] ), giving us elements we require. 
        # This is done by using indexes separated by a colon [x : y]
        # 
        #
        # The UDP package:
        # A: UDP Header [8 Bytes --- 64 Bits]:
        #    1: Source port number -------> 2 bytes 0:7 bits
        #    2: Destination port number --> 2 bytes 8:15 bits
        #    3: Length -------------------> 2 bytes 16:23 bits
        #    4: Checksum -----------------> 2 bytes 24:31 bits
        # B: UDP Body [24 Bytes --- 192 Bits]:
        #    1: Payload Data (if any), app data, message
        # =================================================================================== #


        #extract the fields
        # [0:10]
        length_S = byte_S[0:Packet.length_S_length]

        # [10:20]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length + Packet.seq_num_S_length]
        
        # [20:20 + checksum_length "hex"]
        checksum_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length : Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length]
        
        # [20 + checksum_length "hex": last index]
        msg_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()

        #[TEST]
        print("\n==================================================================================")
        print("\tDebugging Packet")
        print("\tPacket: corrupt(byte_S):")
        print("\t\tPacket: # %d" % ( int(seq_num_S) ) )
        print("\t\tlength_S: " + length_S)
        print("\t\tseq_num_S: " + seq_num_S)
        print("\t\tchecksum_S: " + checksum_S)
        print("\t\tmsg_S: " + msg_S)
        print("\t\tchecksum_length: %d" % (Packet.checksum_length) )
        print("\t\tcomputed_checksum_S: " + computed_checksum_S)
        print("\t\tFinal packet Len: %d" % (len( length_S + seq_num_S + checksum_S + msg_S )) )
        print("==================================================================================\n")

        #and check if the same
        return checksum_S != computed_checksum_S

    def ack(self, seq_num, ack_flag):

        # header_length = self.length_S_length
        # header_checksum = 0 # currently is not used
        # message = len(ack_flag)

        # build acknowledgment packet
        ack_string = "%s" % (ack_flag)
        ack_mess = str(ack_string).zfill(self.ack_nak_length)

        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(seq_num).zfill(self.seq_num_S_length)

        # The packet length: convert length to a byte field of length_S_length bytes
        packet_length = self.length_S_length + len(seq_num_S) + len(ack_mess)

        # fill in the byte field with the packet_length
        length_S = str(packet_length).zfill(self.length_S_length)
        
        #[TEST]
        print("\n==================================================================================")
        print("\tDebugging Packet")
        print("\t\tPacket: # %s" % (seq_num) )
        print("\tPacket: ACK:")
        print("\t\tseq_num_S: " + seq_num_S)
        print("\t\tpacket_length: %d" % (packet_length) )
        print("\t\tlength_S: " + length_S)
        print("\t\tack_mess: " + ack_mess)
        print("\t\tPackeg final string: %s" % (length_S + seq_num_S + ack_mess) )
        print("\t\tFinal packet Len: %d" % (len( length_S + seq_num_S + ack_mess )) )
        print("==================================================================================\n")

        #compile into a string
        return length_S + seq_num_S + ack_mess

    def nak(self, seq_num, nak_flag):

        # header_length = self.length_S_length
        # header_checksum = 0 # currently is not used
        # message = len(nak_flag)

        # build negative acknowledgement
        nak_string = "%s" % (nak_flag)
        nak_mess = str(nak_string).zfill(self.ack_nak_length)

        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(seq_num).zfill(self.seq_num_S_length)

        # The packet length: convert length to a byte field of length_S_length bytes
        packet_length = self.length_S_length + len(seq_num_S) + len(nak_mess)

        # fill in the byte field with the packet_length
        length_S = str(packet_length).zfill(self.length_S_length)
        
        #[TEST]
        print("\n==================================================================================")
        print("\tDebugging Packet")
        print("\tPacket: NAK:")
        print("\t\tPacket: # %s" % (seq_num) )
        print("\t\tseq_num_S: " + seq_num_S)
        print("\t\tpacket_length: %d" % (packet_length) )
        print("\t\tlength_S: " + length_S)
        print("\t\tnak_mess: " + nak_mess)
        print("\t\tPackeg final string: %s" % (length_S + seq_num_S + nak_mess) )
        print("\t\tFinal packet Len: %d" % (len( length_S + seq_num_S + nak_mess )) )
        print("==================================================================================\n")

        #compile into a string
        return length_S + seq_num_S + nak_mess
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1

    ## buffer of bytes read from network
    byte_buffer = '' 

    previous_pkt = None

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        

    def rdt_2_1_send(self, msg_S):

        # =========================================================================================================== #
        '''
        # initialize packet
        p Packet(self.seq_numm msg_S)

        # recieve while seq_num has not increased
        while True:
            
            # get response from reciever
            self.network.udt_send(p.get_byte_S())
            response = ''

            # while there is no response
            while(response == ''):
                # keep receiving 
                response = self.network.udt_receive()

            # get length of response (not sure how)
            length = int(reponse[:Packet.length_S_length])
            
            # find byte buffer (lenght to end of packet)
            self.byte_buffer = response[length:]

            ##################### CHECK FOR CURRUPTION ######################

            # Not currupt:
            if not Packet.corrupt(response[:length])

                # store bytes of packet into array
                packet = Packet.from_byte_S(response[:length])

                # check if seq_num is behind, send ACK if we must continue receiving packets
                if packet.seq_num < self.seq_num:
                    ack = Packet(packet.seq_num, "1")
                    self.network.udt_send(ack.get_byte_S())

                # check if response is ACK, add to seq_num
                elif packet.msg_S == "1":
                    self.seq_num += 1
                    break;
                # check if response is NAK, reset buffer if so
                elif packet.msg_S == "0":
                    self.byte_buffer = ''

            # if packet is corrupt, empty buffer
            if Packet.corrupt(response[:length]):
                self.byte_buffer = ''
        '''
        # =========================================================================================================== #



        # [INFO]
        # =========================================================================================================== #
        # INFO source: https://astro.temple.edu/~stafford/cis320f05/lecture/chap3/deluxe-content.html
        # =========================================================================================================== #

        # FROM DIAGRAM RDT 2.1 sender
        # =========================================================================================================== #
        # Wait for call from API
        # build packet
        # send packet
        # Wait for ACK or NAK
        # Receive packet and check if it is corrupted or NAK: resend packet
        # Receive packet and check if it is corrupted or ACK: Wait for call from API
        # Repeat process
        # =========================================================================================================== #

        # TEST: Receiving ACK or NAK from the Server or Client
        # =========================================================================================================== #
        if msg_S == "1":
            print("\n==================================================================================")
            print("Debugging RDT 2.1 SEND")
            print("Packet: # %d" % (self.seq_num) )
            print("Got ACK message: %s" % (msg_S) )
            print("==================================================================================\n")
        elif msg_S == "0":
            print("\n==================================================================================")
            print("Debugging RDT 2.1 SEND")
            print("Packet: # %d" % (self.seq_num) )
            print("Got NAK message: %s" % (msg_S) )
            print("==================================================================================\n")
        # =========================================================================================================== #

        # DEMO
        # =========================================================================================================== #
        # very first call
        if self.seq_num == 1:

            # Build and send packet
            p = Packet(self.seq_num, msg_S)

            # Save previously sent packet
            self.previous_pkt = p

            self.seq_num += 1
            self.network.udt_send(p.get_byte_S())

        elif msg_S == "1":

            # Build and send packet
            p = Packet(self.seq_num, msg_S)

            # Save previously sent packet
            self.previous_pkt = p

            self.seq_num += 1
            self.network.udt_send(p.get_byte_S())

        elif msg_S == "0":

            # Retrieve previous packet and send packet
            p = self.previous_pkt
            self.network.udt_send(p.get_byte_S())
        # =========================================================================================================== #

        pass
        
    def rdt_2_1_receive(self):

        # FROM DIAGRAM RDT 2.1 sender
        # =========================================================================================================== #
        # Wait for call from API
        # Receive packet and check if it is NOT corrupted and has sequence number:
        # IF is NOT corrupted and has sequence number:
        #   extract data, compute checksum
        #   send ACK packet with: ASK flag and checksum 
        #   deliver data to the application layer
        # IF is corrupted or no sequence number:
        #   compute checksum
        #   send NAC packet with: NAC flag and checksum 
        # Repeat process
        # =========================================================================================================== #

        # receive packet
        # ================================================================================ #
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S

        #keep extracting packets - if reordered, could get more than one
        while True:

            #check if we have received enough bytes
            #not enough bytes to read packet length
            if(len(self.byte_buffer) < Packet.length_S_length):

                # send NAK to the sender
                # sender should resend packet

                #self.rdt_2_1_send("0")

                return ret_S 
            else:
                #extract length of packet
                length = int(self.byte_buffer[:Packet.length_S_length])

                #not enough bytes to read the whole packet
                if len(self.byte_buffer) < length:

                    # send NAK to the sender
                    # sender should resend packet

                    #self.rdt_2_1_send("0")

                    return ret_S
                else:
                    p = Packet
                    isCorrupted = True

                    # Check if packet is corrupted
                    isCorrupted = p.corrupt(self.byte_buffer[0:length])

                    # packet is NOT corrupted
                    if isCorrupted == False:
                        #create packet from buffer content and add to return string
                        p = Packet.from_byte_S(self.byte_buffer[0:length])
                        tmp = p.msg_S
                        #ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S

                        if ret_S is None:
                            ret_S = tmp
                        else:
                            ret_S + tmp
                        
                        
                        # TEST
                        self.rdt_2_1_send("1")

                        print("\n==================================================================================")
                        print("Debugging RDT 2.1 RECEIVE")
                        print("Packet: # %d" % (self.seq_num) )
                        print("ACK message sent")
                        print("==================================================================================\n")

                    elif isCorrupted == True:

                        # TEST
                        # send NAK to the sender
                        # sender should resend packet
                        self.rdt_2_1_send("0")

                        print("\n==================================================================================")
                        print("Debugging RDT 2.1 RECEIVE")
                        print("Packet: # %d" % (self.seq_num) )
                        print("NAK message sent")
                        print("==================================================================================\n")

                        #remove the packet bytes from the buffer
                        self.byte_buffer = self.byte_buffer[length:]
                        break

                    print("\n=====================================")
                    print("RDT: rdt_2_1_receive packet")
                    print("\tlength: %d" % (length) )
                    print("\tisCorrupted: %r" % (isCorrupted) )
                    print("=====================================\n")

                    #remove the packet bytes from the buffer
                    self.byte_buffer = self.byte_buffer[length:]
                    #if this was the last packet, will return on the next iteration


        # ================================================================================ #

        pass
    
    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        