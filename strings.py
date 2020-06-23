import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Qakbot strings decoder.')
    parser.add_argument('-f', type=str, help='Binary file path')
    args = parser.parse_args()

    with open(args.f, 'rb') as f:
        data = f.read()


def extract_strings(key_offset, key_size, cipher_offset):
    """
    Extract Qakbot Strings

    :param key_offset:
    :param key_size:
    :param cipher_offset:
    :return:
    """
    key = data[key_offset:key_offset + key_size]
    cipher = data[cipher_offset:cipher_offset + key_size]
    plain_text = ''

    for i in range(0, key_size):
        plain_text += chr(cipher[i & 0x3F] ^ key[i])

    return plain_text.replace('\x00', '\n')


strings = extract_strings(0x258B8, 0x36F5, 0x2AA30)

with open('strings', 'w') as f:
    f.write(strings)
