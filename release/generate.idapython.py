from idautils import *
from idaapi import *

info = idaapi.get_inf_structure()
bits = 16
if info.is_64bit():
    bits = 64
elif info.is_32bit():
    bits = 32

if bits == 64:
    # we can't PUSH <i64>/RET... so we use RAX, which must be saved before
    #       push rax         ; saved RIP reserve
    #       push rax         ; RAX save
    #       mov rax, <i64>   ; 
    #       mov [rsp+8], rax ; update the saved RIP
    #       pop rax          ; RAX restore
    #       ret              ; RET
    pushret = '505048B8XXXX488944240858C3'
    pushretoffset64 = '13'
    jno_instruction = '70'+pushretoffset64+pushret        # jno <> jo
    jo_instruction = '71'+pushretoffset64+pushret         # jo <> jno
    jnb_instruction = '72'+pushretoffset64+pushret        # jnb <> jb
    jb_instruction = '73'+pushretoffset64+pushret         # jb <> jnb
    jnz_instruction = '74'+pushretoffset64+pushret        # jnz <> jz
    jz_instruction = '75'+pushretoffset64+pushret         # jz <> jnz
    ja_instruction = '76'+pushretoffset64+pushret         # ja <> jna
    jna_instruction = '77'+pushretoffset64+pushret        # jna <> ja
    jns_instruction = '78'+pushretoffset64+pushret        # jns <> js
    js_instruction = '79'+pushretoffset64+pushret         # js <> jns
    jnp_instruction = '7A'+pushretoffset64+pushret        # jnp <> jp
    jp_instruction = '7B'+pushretoffset64+pushret         # jp <> jnp
    jge_instruction = '7C'+pushretoffset64+pushret        # jge <> jl
    jl_instruction = '7D'+pushretoffset64+pushret         # jl <> jge
    jg_instruction = '7E'+pushretoffset64+pushret         # jg <> jle
    jle_instruction = '7F'+pushretoffset64+pushret        # jle <> jg
    jmp_instruction = pushret                             # jmp
    # CALL must be a real CALL in order to handle the RET
    call_instruction = "505048B8XXXX4889442408584883C408FF5424F8"    # call <> push rax / push rax / mov rax <addr> / mov [rsp+8],rax / pop rax / add rsp,8 / call [rsp-8]

if bits == 32:
    pushret = '68XXXXc3'
    pushretoffset86 = '06'
    jno_instruction = '70'+pushretoffset86+pushret        # jno <> jo
    jo_instruction = '71'+pushretoffset86+pushret         # jo <> jno
    jnb_instruction = '72'+pushretoffset86+pushret        # jnb <> jb
    jb_instruction = '73'+pushretoffset86+pushret         # jb <> jnb
    jnz_instruction = '74'+pushretoffset86+pushret        # jnz <> jz
    jz_instruction = '75'+pushretoffset86+pushret         # jz <> jnz
    ja_instruction = '76'+pushretoffset86+pushret         # ja <> jna
    jna_instruction = '77'+pushretoffset86+pushret        # jna <> ja
    jns_instruction = '78'+pushretoffset86+pushret        # jns <> js
    js_instruction = '79'+pushretoffset86+pushret         # js <> jns
    jnp_instruction = '7A'+pushretoffset86+pushret        # jnp <> jp
    jp_instruction = '7B'+pushretoffset86+pushret         # jp <> jnp
    jge_instruction = '7C'+pushretoffset86+pushret        # jge <> jl
    jl_instruction = '7D'+pushretoffset86+pushret         # jl <> jge
    jg_instruction = '7E'+pushretoffset86+pushret         # jg <> jle
    jle_instruction = '7F'+pushretoffset86+pushret        # jle <> jg
    jmp_instruction = pushret                             # jmp
    call_instruction = '68XXXX83C4043EFF5424FC'              # call <> push addr / add esp, 4 / call dword ptr ds:[esp-4]

ins_swaps = []
ins_swaps.append(["js", js_instruction])
ins_swaps.append(["jno", jno_instruction])
ins_swaps.append(["jo", jo_instruction])
ins_swaps.append(["jnp", jnp_instruction])
ins_swaps.append(["jpo", jnp_instruction])
ins_swaps.append(["jp", jp_instruction])
ins_swaps.append(["jpe", jp_instruction])
ins_swaps.append(["jg", jg_instruction])
ins_swaps.append(["jnle", jg_instruction])
ins_swaps.append(["jle", jle_instruction])
ins_swaps.append(["jng", jle_instruction])
ins_swaps.append(["jge", jge_instruction])
ins_swaps.append(["jnl", jge_instruction])
ins_swaps.append(["jns", jns_instruction])
ins_swaps.append(["jl", jl_instruction])
ins_swaps.append(["jnge", jl_instruction])
ins_swaps.append(["jna", jna_instruction])
ins_swaps.append(["jbe", jna_instruction])
ins_swaps.append(["ja", ja_instruction])
ins_swaps.append(["jnbe", ja_instruction])
ins_swaps.append(["jnb", jnb_instruction])
ins_swaps.append(["jae", jnb_instruction])
ins_swaps.append(["jnc", jnb_instruction])
ins_swaps.append(["jb", jb_instruction])
ins_swaps.append(["jc", jb_instruction])
ins_swaps.append(["jnae", jb_instruction])
ins_swaps.append(["jnz", jnz_instruction])
ins_swaps.append(["jne", jnz_instruction])
ins_swaps.append(["jz", jz_instruction])
ins_swaps.append(["je", jz_instruction])
ins_swaps.append(["jmp", jmp_instruction])
ins_swaps.append(["call", call_instruction])

mRegs = {}
p64 = "48"
p64_x2 = "49"
mRegs["eax"] = "b8"
mRegs["ebx"] = "bb"
mRegs["ecx"] = "b9"
mRegs["edx"] = "ba"
mRegs["esi"] = "be"
mRegs["edi"] = "bf"
mRegs["ebp"] = "bd"
mRegs["esp"] = "bc"
mRegs["rax"] = p64+"b8"
mRegs["rbx"] = p64+"bb"
mRegs["rcx"] = p64+"b9"
mRegs["rdx"] = p64+"ba"
mRegs["rsi"] = p64+"be"
mRegs["rdi"] = p64+"bf"
mRegs["rbp"] = p64+"bd"
mRegs["rsp"] = p64+"bc"
mRegs["r8"] = p64_x2+"b8"
mRegs["r9"] = p64_x2+"b9"
mRegs["r10"] = p64_x2+"ba"
mRegs["r11"] = p64_x2+"bb"
mRegs["r12"] = p64_x2+"bc"
mRegs["r13"] = p64_x2+"bd"
mRegs["r14"] = p64_x2+"be"
mRegs["r815"] = p64_x2+"bf"


base = get_imagebase()
end = get_last_seg().endEA
name = GetInputFile() 

# converts an instruction to a "moved" instruction block
# returns:
#   resulting opcodes
#   relocs (relative offset which must be converted to an absolute address by the DLL)
def get_instruction(addr, f_addr):
    global ins_swaps, base, end, bits, mRegs

    if bits != 32 and bits != 64:
        print "[!] Unsupported architecture"
        return None

    neededBytes = 5
    if bits == 64:
        neededBytes = 13

    mn = GetMnem(addr)
    instruction_found = False
    
    # check for obvious swaps
    for x in ins_swaps:
        if mn.lower() == x[0].lower():
            # x86 => 0xFF prefix is an absolute one (not on x64)
            if mn.lower() in ("call", "jmp") and bits == 32 and Byte(addr) == 0xFF:
                break
            instruction_found = True
            # register? If yes, then skip this one
            if GetOpType(addr, 0) == 1:
                break
                
            ref_addr = GetOperandValue(addr, 0)
            # is it a correct address?
            if ref_addr < base:             
                print "[!] Erreur, le JUMP a "+hex(addr).replace("L","")+" semble invalide. Pas de patch possible."
                return None
                
            # does it "jumps" on our moved bytes?
            if ref_addr >= f_addr and ref_addr <= f_addr + neededBytes:
                break
            
            # otherwise, lets convert it to an absolute address
            ref_addr = ref_addr - base

            # and just patch the opcode
            pz = x[1].find("XXXX")
            if bits == 32:
                return (x[1][:pz].decode("hex") + struct.pack("<L", ref_addr) + x[1][pz+4:].decode("hex"), pz/2)
            else:
                return (x[1][:pz].decode("hex") + struct.pack("<Q", ref_addr) + x[1][pz+4:].decode("hex"), pz/2)

           
    # not found: let's get the instructions
    instruction = GetManyBytes(addr, ItemSize(addr))
    reloc = 0
    if instruction_found is False:
        x = 0
        while True:
            # value?
            n = GetOperandValue(addr, x)
            if n == -1:
                break

            # does it seems to be an in-module adress (function, data...)?
            if n > base and n < end:
                # what's the module's offset?
                if bits == 32:
                    reloc = instruction.find(struct.pack("<L", n))
                else:
                    reloc = instruction.find(struct.pack("<Q", n))
                # patch the opcode
                if reloc > 0 and reloc is not None:
                    if bits == 32:
                        instruction = instruction.replace(struct.pack("<L", n), struct.pack("<L", n - base))
                    else:
                        instruction = instruction.replace(struct.pack("<Q", n), struct.pack("<Q", n - base))
                    break

                # not found: it may be a relative one (LEA)
                if mn == "lea":
                    # let's convert to MOV <absolute>
                    if GetOpType(addr, 0) == 1:
                        rdest = GetOpnd(addr,0)
                        if mRegs.has_key(rdest):
                            if rdest[0] == "e":
                                return (mRegs[rdest].decode("hex") + struct.pack("<L", n - base), len(mRegs[rdest]) / 2)
                            return (mRegs[rdest].decode("hex") + struct.pack("<Q", n - base), len(mRegs[rdest]) / 2)

                # ouch, not found, crash!
                print "[!] Erreur, impossible de parser l'adresse 0x%x : elle reference visiblement une adresse du module courant, mais impossible d'identifier l'opcode responsable."% (addr)
                return None
            x = x+1
    return (instruction, reloc)

# gets the T1... opcodes. From registers only (not RAX).
def getT1Opcodes(regBuffer, regSize):
    if bits == 64 and regBuffer == "rax":
        print "Sorry, but RAX can't be used. You MAY use it, but you will have to patch several routines. Can't you find another address where RAX is moved to another register?"
        return

    # prefix
    dumper = {}
    prefix32bits = '89'
    prefix64bits = '4889'
    suffix8bits32 = '81e2ff000000'
    suffix16bits32 = '81e2ffff0000'
    suffix8bits64 = '4881e2ff000000'
    suffix16bits64 = '4881e2ffff0000'

    # mov opcodes
    prefx = prefix32bits
    if bits == 64:
        prefx = prefix64bits
    dumper["ax"] = [prefx+'C1',prefx+'C2']           # mov ecx, eax
    dumper["bx"] = [prefx+'D9',prefx+'D1']           # mov ecx, ebx
    dumper["cx"] = ['',prefx+'ca']             # rien
    dumper["dx"] = [prefx+'d1','']
    dumper["si"] = [prefx+'F1',prefx+'F2']
    dumper["di"] = [prefx+'F9',prefx+'FA']
    dumper["r8"] = ['4c89c1','4c89c2']
    dumper["r9"] = ['4c89c9','4c89cA']
    dumper["r10"] = ['4c89d1','4c89d2']
    dumper["r11"] = ['4c89d9','4c89dA']
    dumper["r12"] = ['4c89e1','4c89e2']
    dumper["r13"] = ['4c89e9','4c89ea']
    dumper["r14"] = ['4c89f1','4c89f2']
    dumper["r15"] = ['4c89f9','4c89fa']

    # RCX/RDX exchanges
    swap32bits = '89C889D189C2'
    swap64bits = '4889C84889D14889C2'

    rBufferSize = 0
    if regBuffer[0] == "e":
        rBufferSize = 32
        regBuffer = regBuffer[1:]
    elif regBuffer[0] == "r":
        rBufferSize = 64
        if len(regBuffer) > 2 and regBuffer[1] != '1':
            regBuffer = regBuffer[1:]

    rSizeSize = 0
    if regSize[0] == "e":
        rSizeSize = 32
        regSize = regSize[1:]
    elif regSize[0] == "r":
        rSizeSize = 64
        if len(regSize) > 2 and regSize[1] != '1':
            regSize = regSize[1:]
    elif regSize[1] == "l":
        rSizeSize = 8
        regSize = regSize[1]+"x"
    elif regSize[1] == "x":
        rSizeSize = 16

    if rSizeSize == 0 or rBufferSize == 0 or not dumper.has_key(regBuffer) or not dumper.has_key(regSize):
        print "[+] Bad parameter: specify a 8,16,32,64 bit register. 'H' registers (AH, BH...) and XMM ones are not supported (yet)."
        return

    t1Opcodes = ""
    # swap?
    if regBuffer == "dx" and regSize == "cx":
        if bits == 32:
            t1Opcodes = swap32bits
        else:
            t1Opcodes = swap64bits
    else:
        # swap swap?
        if regSize == "cx":
            t1Opcodes = dumper[regSize][1]
            t1Opcodes += dumper[regBuffer][0]
        else:
            t1Opcodes = dumper[regBuffer][0]
            t1Opcodes += dumper[regSize][1]

    # don't forget the ANDS for registers subsets
    if rSizeSize == 8:
        if bits == 32:
            t1Opcodes += suffix8bits32
        else:
            t1Opcodes += suffix8bits64
    elif rSizeSize == 16:
        if bits == 32:
            t1Opcodes += suffix16bits32
        else:
            t1Opcodes += suffix16bits64

    return t1Opcodes

# loads the config file
def loadConfig(fileName):
    try:
        x = open(fileName,"rb").read()
        return x
    except:
        pass
    return None

# gets the config
def getConfigEntries(conf):
    cpt = 0
    entries = []
    while len(conf) > 4:
        configData = conf
        sz = struct.unpack("<L", configData[:4])[0]
        configData = configData[4:]
        x = struct.unpack("<H", configData[:2])[0]
        configData = configData[2:]
        modName = configData[:x-1]
        configData = configData[x:]
        modOffset = struct.unpack("<L", configData[:4])[0]
        entries.append((modName, modOffset))
        conf = conf[sz:]
        cpt += 1
    return entries

print 'updateConfig(fileName="config.bin", overwrite = False) : saves the sconfig. Caution: by default existing configuration file will be extended, not replaced!'
def updateConfig(fileName="config.bin", overwrite = False):
    global config
    if len(config) == 0:
        print "[!] Empty configuration!"
        return

    full_config = config
    if overwrite is False:
        x_config = loadConfig(fileName)
        if x_config is not None:
            print "[+] Loading existing configuration"
            full_config += x_config

    all_entries = getConfigEntries(full_config)
    print "[+] Checking for conflicts..."
    if len(set(all_entries)) != len(all_entries):
        print "[!] Conflicts found! Choose another file or reset your actual config (config='')!"
        return

    print "[+] Writing %s" % (fileName)
    try:
        if overwrite is True:
            open(fileName,"wb").write(config)
        else:
            open(fileName,"ab").write(config)

    except Exception as e:
        print "[!] Exception caught while saving: %s" % (e)
        print "Raw configuration: "+config.encode("hex")
        print "You may find the config data in the 'config' global or in this function return value."
        return config
        pass
    return

print 'printConfig(fileName="config.bin"): prints the current config and the one in the specified file.'
def printConfig(fileName="config.bin"):
    global config
    conf = config
    try:
        x = open(fileName, "rb").read()
        conf = x + conf
    except:
        pass
    print "Hooks:"
    cdata = getConfigEntries(conf)
    for x,y in cdata:
        print x+ ": "+ hex(y)
    return

print 'printFullConfig() : prints the config (details).'
def printFullConfig():
    global config
    configData = config
    cpt = 0
    while len(configData)>4:
        print "Configuration #%d" % (cpt)
        print "\ts.dwSize: %x" % (struct.unpack("<L", configData[:4])[0])
        configData = configData[4:]

        x = struct.unpack("<H", configData[:2])[0]
        print "\ts.modNameSize: %x" % (x)
        configData = configData[2:]

        print "\ts.modName: %s" % (configData[:x])
        configData = configData[x:]

        print "\ts.moduleOffset: %x" % (struct.unpack("<L", configData[:4])[0])
        configData = configData[4:]

        print "\ts.nopsSize: %x" % (struct.unpack("<H", configData[:2])[0])
        configData = configData[2:]

        x = struct.unpack("<H", configData[:2])[0]
        print "\ts.t1OpcodesSize: %x" % (x)
        configData = configData[2:]

        print "\ts.t1Opcodes: %s" % (configData[:x].encode("hex"))
        configData = configData[x:]

        x = struct.unpack("<H", configData[:2])[0]
        print "\ts.t2OpcodesSize: %x" % (x)
        configData = configData[2:]
        print "\ts.t2Opcodes: %s" % (configData[:x].encode("hex"))
        configData = configData[x:]

        x = struct.unpack("<H", configData[:2])[0]
        print "\ts.relocsCount: %x" % (x)
        configData = configData[2:]
        print "\trelocs: %s" % (configData[:x*4].encode("hex"))
        configData = configData[x*4:]
        cpt += 1
    return

config = ""
print "getHook(address, regBuffer = None, regSize = None, t1customOpcodes = None): registers a new hook on regBuffer/regSize. t1customOpcodes may be set in the regBuffer param if regSize is None."
def getHook(address, regBuffer = None, regSize = None, t1customOpcodes = None):
    global bits, base, end, name, config

    if bits != 32 and bits != 64:
        print "[!] Unsupported architecture"
        return

    # generate T1 opcodes
    t1Opcodes = t1customOpcodes
    if regBuffer != None and regSize != None:
        t1Opcodes = getT1Opcodes(regBuffer,regSize)
    if regSize == None and t1customOpcodes == None and regBuffer != None:
        t1Opcodes = regBuffer

    if t1Opcodes == None:
        print "[!] Usage: getHook(address, regBuffer, regSize, t1customOpcodes)"
        print "\taddress: address where you want to place the interception point. You need 5 (x86) or 12 (x64) bytes without any X-ref (except if you're at the start of a BB)"
        print "\tregBuffer / regSize: buffer/size registers. Just give their names. XMM and 'H' registers (ah, bh...) are not supported."
        print "\tt1customOpcodes: custom opcodes. You must:"
        print "\t\t- put the buffer address in the ECX (RCX) register"
        print "\t\t- put the buffer size in the EDX (RDX) register"
        print "\t\t- not mess up with ESP (RSP)"
        print ""
        print "Exemples:"
        print "\tgetHook(here(), 'rax','r10')"
        print "\tgetHook(here(), 'ax','bl')"
        print "\tgetHook(here(), t1customOpcodes = '488B088B5008') // mov rcx,[rax] ; mov rdx, [rax+8]"
        print ""
        return

    # needed size
    neededBytes = 5
    if bits == 64:
        neededBytes = 13

    # first, get the T2 trampoline
    curPtr = address
    relocs = []
    nopsSize = 0
    t2Bytes = ''
    overwritenBytes = ""

    # move instructions as long as the size requirement is not fullfiled
    while len(overwritenBytes) < neededBytes:

        # XREF found, and not within the moved bytes => block
        if curPtr != address:
            x = get_first_cref_to(curPtr)
            x = get_next_cref_to(curPtr, x)
            while x != BADADDR:
                if x < address or x > address + neededBytes:
                    print "[!] You can't place a hook here, there are existing X-REFs :/."
                    print "\tFaulting address: "+hex(curPtr)+" is referenced by "+hex(x)
                    return 
                x = get_next_cref_to(curPtr, x)

        curPtr2 = NextHead(curPtr)
        overwritenBytes += GetManyBytes(curPtr, curPtr2-curPtr)
        # get the moved instruction
        ins = get_instruction(curPtr, address)
        if ins is None:
            return
        instruction, reloc = ins
        if reloc != 0:
            reloc += len(t2Bytes)
            relocs.append(reloc)
        t2Bytes += instruction
        curPtr = curPtr2

    nopsSize = curPtr - address
    # now, let's prepare our trampolines
    if bits == 32:
        # PUSHAD/PUSHFD
        t1Bytes = "609c".decode("hex")
        # place the T1 opcodes
        t1Bytes += t1Opcodes.decode("hex")
        # trampoline ends with 
        #   PUSH 0xFAD0FAD0     // trampoline ID
        #   MOV EAX, DEADBEEF   // log function address
        #   CALL EAX            // call log function
        #   PUSH F00DF00D       // T2 address
        #   RET
        # REMARK: if you want to use EAX => patch here!
        t1Bytes += "68D0FAD0FAB8EFBEADDEFFD0680df00df0C3".decode("hex")

        # T2 starts with POP REG/POPFD/POPAD/POP EAX and ends with PUSH F0F0F0F0/RET
        t2Bytes = "9D61".decode("hex") + t2Bytes + "68f0f0f0f0C3".decode("HEX")
        for i in range(len(relocs)):
            relocs[i] = relocs[i] + len(popafd.decode("hex"))

    if bits == 64:
        # x64 => no pushaq/popaq :(
        # pushfq / push rax / push rbx / push rcx / push rdx / push r8 / push r9 / push r10 / push r11 / push r12 / push r13 / push r14 / push r15 / push rsi / push rdi / push rbp
        pushafq = "9C5053515241504151415241534154415541564157565755"
        t1Bytes = pushafq.decode("hex")
        # T1
        t1Bytes += t1Opcodes.decode("hex")
        # T1 ends with :
        #   MOV R8, 0xfad0fad0fad0fad0          // trampoline ID
        #   MOV RAX, 0xbad0bad0bad0bad0         // log function address
        #   SUB RSP,0x20                        // __fastcall
        #   CALL EAX                            // call log function
        #   ADD RSP,0x20                        // __fastcall
        #   MOV RAX, 0xF0d0F0d0F0d0F0d0         // T2 address
        #   PUSH RAX
        #   RET
        t1Bytes += "49B8D0FAD0FAD0FAD0FA48B8D0BAD0BAD0BAD0BA4883EC20FFD04883c42048B8D0F0D0F0D0F0D0F050C3".decode("hex") 

        # POPAQ!
        popafq = "5D5F5E415F415E415D415C415B415A415941585A595B589D" + "58"
        # POPAFQ, savec instructions, PUSH F0F0F0F0F0F0F0F0, RET
        t2Bytes = popafq.decode("hex") + t2Bytes + "505048B8F0F0F0F0F0F0F0F0488944240858C3".decode("HEX")
        for i in range(len(relocs)):
            relocs[i] = relocs[i] + len(popafq.decode("hex"))

    # generate config struct
    xStruct = struct.pack("<H", len(name)+1)
    xStruct += name + "\x00"
    xStruct += struct.pack("<L", address - base)
    xStruct += struct.pack("<H", nopsSize)
    xStruct += struct.pack("<H", len(t1Bytes))
    xStruct += t1Bytes
    xStruct += struct.pack("<H", len(t2Bytes))
    xStruct += t2Bytes
    xStruct += struct.pack("<H", len(relocs))
    for i in relocs:
        xStruct += struct.pack("<L", i)
    xStruct = struct.pack("<L",len(xStruct) + 4)+xStruct

    config += xStruct
    print "[+] Config updated!"
    return

print "help(): HELP!"
def help():

    print "[!] Usage: "
    print "\t use getHook() to place a hook"
    print "\t use updateConfig() to save your config or update an existing one"
    print "\t use printConfig() to print your actual config"
    print ""
    print "Examples:"
    print "\tgetHook(here(), 'rax','r10')"
    print "\tgetHook(here(), t1customOpcodes = '488B088B5008') // mov rcx,[rax] ; mov rdx, [rax+8]"
    print "\tupdateConfig('test.bin',True)"
    print ""
    return