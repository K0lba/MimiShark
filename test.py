# text = '0025043F043504400435043004340440043504410025043204410435044500200432044B0437043E0432043E04320025'
# # text = '0026622f4787001d60b3018408004500003ccb5b4000400628e4c0a8018cae8fd5b8e14e00508e50190100000000a00216d08f470000020405b40402080a0021d25a0000000001030307'.replace(' ','')
# string = str(bytes.fromhex(text))
# # temp  =[]
# # for b in string.split('\\x'):
# #     if(b=="b'"):
# #         continue
# #     if(len(b)==2):
# #         temp.append('.')
# #         continue
# #     temp.append(b[2:].replace("'",''))
# # print(temp)
# # print(''.join(temp))
# print((bytes.fromhex(text)).decode('UTF-16-be'))
f = open("pcap.json")
a = f.read()
print(a.replace(' ','').replace('\n','')[947])

result = ''
word = "01:00:5e:00:00:fb:be:c0:33:7d:00:b9:08:00:45:00:00:8c:61:5c:00:00:ff:11:b7:f5:c0:a8:00:6b:e0:00:00:fb:14:e9:14:e9:00:78:6f:b4:00:00:00:00:00:03:00:00:00:00:00:01:0f:5f:63:6f:6d:70:61:6e:69:6f:6e:2d:6c:69:6e:6b:04:5f:74:63:70:05:6c:6f:63:61:6c:00:00:0c:00:01:08:5f:68:6f:6d:65:6b:69:74:c0:1c:00:0c:00:01:0c:5f:73:6c:65:65:70:2d:70:72:6f:78:79:04:5f:75:64:70:c0:21:00:0c:00:01:00:00:29:05:a0:00:00:11:94:00:12:00:04:00:0e:00:5c:36:c5:e0:f5:3e:80:be:c0:33:7d:00:b980:30:49:0f:a1:55:be:c0:33:7d:00:b9:86:dd:60:03:00:00:00:78:11:ff:fe:80:00:00:00:00:00:00:04:0f:44:52:9a:78:44:96:ff:02:00:00:00:00:00:00:00:00:00:00:00:00:00:fb:14:e9:14:e9:00:78:eb:d4:00:00:00:00:00:03:00:00:00:00:00:01:0f:5f:63:6f:6d:70:61:6e:69:6f:6e:2d:6c:69:6e:6b:04:5f:74:63:70:05:6c:6f:63:61:6c:00:00:0c:00:01:08:5f:68:6f:6d:65:6b:69:74:c0:1c:00:0c:00:01:0c:5f:73:6c:65:65:70:2d:70:72:6f:78:79:04:5f:75:64:70:c0:21:00:0c:00:01:00:00:29:05:a0:00:00:11:94:00:12:00:04:00:0e:00:5c:36:c5:e0:f5:3e:80:be:c0:33:7d:00:b9".split(":")
# print(word)
for i in word:
    a = bytes.fromhex(i)
    b = str(a)[2:len((str(a)))-1]
    if(len(b)<2):
        result += b
    else:
        result+= '.'


def ascii(let):
    binary_int = int(let, 16)
    byte_number = binary_int.bit_length() + 7 // 8
    binary_array = binary_int.to_bytes(byte_number, "big")
    ascii_text = binary_array.decode()
    print( ascii_text)

print(result.replace("b'\\x",'').replace("'",''))
# print(bytes.fromhex('01'))
# print(ascii('60'))