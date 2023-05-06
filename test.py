text = '0025043F043504400435043004340440043504410025043204410435044500200432044B0437043E0432043E04320025'
# text = '0026622f4787001d60b3018408004500003ccb5b4000400628e4c0a8018cae8fd5b8e14e00508e50190100000000a00216d08f470000020405b40402080a0021d25a0000000001030307'.replace(' ','')
string = str(bytes.fromhex(text))
# temp  =[]
# for b in string.split('\\x'):
#     if(b=="b'"):
#         continue
#     if(len(b)==2):
#         temp.append('.')
#         continue
#     temp.append(b[2:].replace("'",''))
# print(temp)
# print(''.join(temp))
print((bytes.fromhex('0800')).decode('UTF-16-be'))