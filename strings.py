#Qbot strings decryption
#@author dark0pcodes
#@category Malware Analysis
#@keybinding 
#@menupath 
#@toolbar 


import ghidra.app.script.GhidraScript
import exceptions

enc_buffer = []

listing = currentProgram.getListing()

add_mw_xor_str = 0x40658b
add_mw_xor_str_cdecl = 0x4064f7
key_offset = 0x40b898
data_offset = 0x410130
key_size = 0x373a

def decrypt_str(str_offset):
    key, cipher = [], []    

    for i in range(0, key_size):
    	key.append(getByte(toAddr(key_offset + i)) & 0xFF)
        cipher.append(getByte(toAddr(data_offset + i)) & 0xFF)

    j = 0
    plain_text = ''
    char = ''

    while char != '\x00':
        char = chr(cipher[(str_offset + j) & 0x3F] ^ key[str_offset + j])
        plain_text += char
        j += 1
    return plain_text


def run():
    for ref in getReferencesTo(toAddr(add_mw_xor_str)):
        callee = ref.getFromAddress()
	inst = getInstructionAt(callee)

	print("Callee: %s" % callee)
	comm = callee
        i = 0 

	while i < 50:
            inst = getInstructionBefore(inst)
            
            if 'MOV EAX' in inst.toString():
                try:
                    string = decrypt_str(int(inst.toString().split(',')[1][2:], 16))
                except ValueError:
                    break

                print("String: %s" % string)

                codeUnit = listing.getCodeUnitAt(comm)
		codeUnit.setComment(codeUnit.EOL_COMMENT, string)

                break

            i += 1


    for ref in getReferencesTo(toAddr(add_mw_xor_str_cdecl)):
        callee = ref.getFromAddress()
	inst = getInstructionAt(callee)

	print("Callee: %s" % callee)
	comm = callee
        i = 0 

	while i < 50:
            inst = getInstructionBefore(inst)
            
            if 'PUSH 0x' in inst.toString():
                string = decrypt_str(int(inst.toString().split(' ')[1][2:], 16))
                print("String: %s" % string)

                codeUnit = listing.getCodeUnitAt(comm)
		codeUnit.setComment(codeUnit.EOL_COMMENT, string)

                break

            i += 1

run()
