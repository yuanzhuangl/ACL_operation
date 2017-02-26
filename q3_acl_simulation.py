#copyright Yuan-B00755386
#Python 3

#define read and write text file function
def read_file(file_name):
    File = []
    with open('Input/%s'%file_name,"r") as f:
        for line in f:
            File.append(line.strip().split(' '))
    return File
def write_file(file_name,list):
    with open('Output/%s'%file_name,"w") as f:
        for line in list:
            f.write(' '.join(line))

#check each line of standard acl
def check_ip_standard(acl_line,packet_line):
    packet_source_set = packet_line[0].split('.')#split source ip address of packet into 4 items list
    acl_source_set = acl_line[3].split('.')#split source ip address of the acl line into 4 items list
    acl_mask_set = acl_line[4].split('.')#split source mask of the acl line into 4 items list
    for i in range(4):
        if acl_mask_set[i] == '0': #if 0 in mask, then check
            if acl_source_set[i] != packet_source_set[i]:
                return False #address does not match so return false
            else:
                continue
    return True

def check_ip_extended(acl_line,packet_line):
    packet_souce_set = packet_line[0].split('.')
    packet_dest_set = packet_line[1].split('.')
    #split source and destionation ip address of packet into 4 items list each
    source_ip_set = acl_line[4].split('.')
    source_mask_set = acl_line[5].split('.')
    dest_ip_set = acl_line[6].split('.')
    dest_mask_set = acl_line[7].split('.')
    # split ip and mask addresses of the acl line into 4 items list each
    for i in range(4):
        if source_mask_set[i] == '0':   #if 0 in mask, then check
            if source_ip_set[i] != packet_souce_set[i]:
                return False    #address does not match so return false
        if dest_mask_set[i] == '0':     #if 0 in mask, then check
            if dest_ip_set[i] != packet_dest_set[i]:
                return False    #address does not match so return false
        if len(acl_line)>=9:
            if acl_line[8].split('.')[1] != packet_line[2]:
                return False    #protocol does not match so return false
    print(packet_line)
    return True


def ACL_operation(acl,packets):
    dict = {'deny':'Denied','permit':'permitted'}
    if len(acl[0])==5 :
        for item in packets: #check each packet
            for line in acl: #check if packet match line in acl
                if line[0] == 'access-list':
                    if len(item) < 3 and len(line) < 4:
                        item.append('denied\n')
                    else:
                        if check_ip_standard(line,item) == True:
                            item.append('%s\n'%dict[line[2]])
                            break
                        else:
                            continue
                    #if the address can not match all acls,then deny
    if len(acl[0]) >= 8:
        for item in packets: #check each packet
            for line in acl:#check if packet match line in acl
                if line[0] == 'access-list':
                    if len(item) < 4 and len(line) <4:
                        item.append('denied\n')
                    else:
                        if check_ip_extended(line, item) == True:
                            item.append('%s\n' % dict[line[2]])
                            break
                        else:
                            continue
                    # if the address can not match all acls,then deny
    return packets


if __name__ == '__main__':
    acl = read_file('ACL')
    packets = read_file('Packets')
    # read standard acl files
    extended_acl = read_file('Extended_ACL')
    extended_packets = read_file('Extended_Packets')
    # read extended acl files
    write_file('Packets_out',ACL_operation(acl,packets))
    write_file('Exteneded_Packets_out', ACL_operation(extended_acl, extended_packets))
    # call operation functions