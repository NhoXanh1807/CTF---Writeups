import subprocess, sys, os
import shlex

usb_codes = {
    "0x04": ['a','A'], "0x05": ['b','B'], "0x06": ['c','C'], "0x07": ['d','D'],
    "0x08": ['e','E'], "0x09": ['f','F'], "0x0A": ['g','G'], "0x0B": ['h','H'],
    "0x0C": ['i','I'], "0x0D": ['j','J'], "0x0E": ['k','K'], "0x0F": ['l','L'],
    "0x10": ['m','M'], "0x11": ['n','N'], "0x12": ['o','O'], "0x13": ['p','P'],
    "0x14": ['q','Q'], "0x15": ['r','R'], "0x16": ['s','S'], "0x17": ['t','T'],
    "0x18": ['u','U'], "0x19": ['v','V'], "0x1A": ['w','W'], "0x1B": ['x','X'],
    "0x1C": ['y','Y'], "0x1D": ['z','Z'], "0x1E": ['1','!'], "0x1F": ['2','@'],
    "0x20": ['3','#'], "0x21": ['4','$'], "0x22": ['5','%'], "0x23": ['6','^'],
    "0x24": ['7','&'], "0x25": ['8','*'], "0x26": ['9','('], "0x27": ['0',')'],
    "0x28": ['\n','\n'], "0x29": ['[ESC]','[ESC]'], "0x2A": ['[BACKSPACE]','[BACKSPACE]'],
    "0x2B": ['\t','\t'], "0x2C": [' ',' '], "0x2D": ['-','_'], "0x2E": ['=','+'],
    "0x2F": ['[','{'], "0x30": [']','}'], "0x31": ['\\','|'], "0x32": ['#','~'],
    "0x33": [';',';'], "0x34": ["'",'"'], "0x36": [',','<'], "0x37": ['.','>'],
    "0x38": ['/','?'], "0x39": ['[CAPSLOCK]','[CAPSLOCK]'], "0x3A": ['F1'], "0x3B": ['F2'],
    "0x3C": ['F3'], "0x3D": ['F4'], "0x3E": ['F5'], "0x3F": ['F6'], "0x41": ['F7'],
    "0x42": ['F8'], "0x43": ['F9'], "0x44": ['F10'], "0x45": ['F11'], "0x46": ['F12'],
    "0x4F": ['→','→'], "0x50": ['←','←'], "0x51": ['↓','↓'], "0x52": ['↑','↑']
}

def keystroke_decoder(filepath, field):
    out = subprocess.run(shlex.split(f"tshark -r {filepath} -Y \"{field}\" -T fields -e {field}"), capture_output=True)
    output = out.stdout.split()
    message = []

    for raw in output:
        buffer = str(raw)[2:-1]  # remove b''

        if len(buffer) < 18:
            continue

        buffer = buffer[2:]  # bỏ byte đầu tiên → còn 8 byte (16 hex)
        modifier_hex = buffer[0:2]
        keycode_hex = buffer[4:6]

        keycode = f"0x{keycode_hex.upper()}"

        # Kiểm tra nếu không có phím bấm
        if keycode == "0x00":
            continue

        # Phím backspace
        if keycode == "0x2A" and message:
            message.pop()
            continue

        # Có trong bảng mã
        if keycode in usb_codes:
            modifier = int(modifier_hex, 16)
            is_shift = modifier & (1 << 1) or modifier & (1 << 5)  # bit 1 (LShift) hoặc bit 5 (RShift)
            message.append(usb_codes[keycode][1 if is_shift else 0])

    return message

# Main
if len(sys.argv) != 2 or not os.path.exists(sys.argv[1]):
    print("\nUsage : python Usb_Keyboard_Parser.py <filepath>")
    exit(1)

filepath = sys.argv[1]
function_call = keystroke_decoder(filepath, "usb.capdata")

hid_data = ''.join(function_call)

if not hid_data:
    function_call = keystroke_decoder(filepath, "usbhid.data")
    print("\n[+] Using filter \"usbhid.data\" Retrieved HID Data is:\n")
    print(''.join(function_call))
else:
    print("\n[+] Using filter \"usb.capdata\" Retrieved HID Data is:\n")
    print(hid_data)
