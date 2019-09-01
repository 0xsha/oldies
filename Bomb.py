# /usr/local/bin/python

# -------------------------------------------------------------------------------
# Name:        Boomb-Defuser.py
# Purpose:     Defuse Binary Bomb
#
# Author:      0xSha
# Twitter:     @0xSha
#
# Copyright:   (c) 0xSha.io
# Licence:     GPL v3
# -------------------------------------------------------------------------------

# intermezzo coding style o_O

# import stuff
import string
import ast


# simple linked list class
class Node:
     '''
    Simple LinkedList Class
    @cargo    : str
    @nextp    : next pointer
    @return node
    '''
    def __init__(self, cargo=None, nextp=None):
        self.cargo = cargo
        self.next  = nextp

    def __str__(self):
        return str(self.cargo)

def list_node(node):
     '''
    Take a node and append as string 
    @node   : node to append
    @return list of added nodes 
    '''
    lst = []
    while node:
        lst.append(str(node))
        node = node.next
    return lst    
    
def phase_six():
     '''
    Solve Phase_Six 
    @param   : void
    @return solution to phase_six 
    '''
    node1 = Node({0x1B0:"6"})
    node2 = Node({0x0D4:"5"})
    node3 = Node({0x3E5:"4"})
    node4 = Node({0x12D:"3"})
    node5 = Node({0x2D5:"2"})
    node6 = Node({0x0FD:"1"})
    
    node1.next = node2
    node2.next = node3
    node3.next = node4
    node4.next = node5
    node5.next = node6
    dic_node = {}
    for str_node in list_node(node1):
        dic_node.update (ast.literal_eval(str_node))
        
    print "phase_six  :",    
    for item in sorted(dic_node,reverse=True):
        print dic_node[item],
    
def phase_one():
    '''
    Solve Phase_One 
    @param   : void
    @return solution to phase_one
    '''
    return "phase_one  : Public speaking is very easy."

def phase_two():
         '''
    Solve Phase_Six 
    @param   : void
    @return [i+i]*i sulution to phase_two 
    '''
    lst = []
    for i in xrange(1,7):
        lst.append(i)
    final = []
    for x in range(len(lst)):
        final.append(str(reduce(lambda x, y: x*y,lst[:x+1])))
    done = ' '.join(final)
    return "phase_two  : " + done 
             
             
def phase_four(input_num):
    '''
    Solve Phase_four
    @input_num   : integer to check
    @return solution to phase_for recursion 
    '''
    temp=0
    result = 0
    if (input_num>1):
        temp = phase_four(input_num-1)
        result = temp + phase_four(input_num-2)
        if result == 55:
            print "phase_four : %d" % input_num             
    else:
        result =1       
    return result


def phase_five(input_string):
    '''

    Solve Phase_Five 
    @input_string   : string to compare
    @return ASCII string solution to phase_five using custom_table 

    custom_table:
    
    .data:00404580                 db  69h ; i
    .data:00404581                 db  73h ; s
    .data:00404582                 db  72h ; r
    .data:00404583                 db  76h ; v
    .data:00404584                 db  65h ; e
    .data:00404585                 db  61h ; a
    .data:00404586                 db  77h ; w
    .data:00404587                 db  68h ; h
    .data:00404588                 db  6Fh ; o
    .data:00404589                 db  62h ; b
    .data:0040458A                 db  70h ; p
    .data:0040458B                 db  6Eh ; n
    .data:0040458C                 db  75h ; u
    .data:0040458D                 db  74h ; t
    .data:0040458E                 db  66h ; f
    .data:0040458F                 db  67h ; g

         
'''
    static_string = input_string
    custom_table = [0x69,0x73,0x72,0x76,0x65,0x61,0x77,0x68,0x6f,0x62,0x70,0x6e,0x75,0x74,0x66,0x67]
    result = ""
    for char_index in range(0,6):
        for input_character in string.printable:
                if static_string[char_index] == chr(custom_table[(ord(input_character) & 0xF)]):
                    result += input_character
                    # print input_character.encode('hex')
                    break
        char_index+=1
    return "phase_five : %s" % result

    
if __name__=='__main__':
    # here is just calling functions
    print "[+] defusing the bomb ...."
    print phase_one()
    print phase_two()
    for i in xrange(0,10):
        phase_four(i)
    print phase_five("giants")
    phase_six()
    print "\n[+] the bomb has been defused do secret_phase by your self ;)"
    
