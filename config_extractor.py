import os

import pefile
from arc4 import ARC4

BRIEFLZ_HEADER = b'\x62\x6C\x7A\x1A\x00\x00\x00\x01'
QBOT_HEADER = b'\x61\x6c\xd3\x1a\x00\x00\x00\x01'


def extract_resource(file_path, res_name):
    """
    Given the file and resource name, return the resource content

    :param file_path:
    :param res_name:
    :return:
    """
    pe = pefile.PE(file_path)

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        if resource_id.name.string.decode() == res_name:
                            return pe.get_data(
                                resource_id.directory.entries[0].data.struct.OffsetToData,
                                resource_id.directory.entries[0].data.struct.Size
                            )


def qbot_decompress(data):
    with open('tmp_file', 'wb') as g:
        g.write(BRIEFLZ_HEADER.join(data.split(QBOT_HEADER)))

    os.system('./blzpack -d tmp_file example.out')

    with open('example.out', 'rb') as g:
        data = g.read()

    os.remove('tmp_file')
    os.remove('example.out')

    return data


def decrypt_resource(res_data):
    """
    RC4 Qakbot decryption

    :param res_data:
    :return:
    """
    buffer = ARC4(res_data[0:20]).decrypt(res_data[20:])

    if QBOT_HEADER in buffer:
        return qbot_decompress(buffer[20:])
    return buffer[20:]


if __name__ == '__main__':
    if not os.path.exists('output'):
        os.mkdir('output')

    unpacked = input('Insert Qakbot unpacked payload: ')

    try:
        cipher = extract_resource(unpacked, '307')

        if cipher:
            print('[+] Extracting embedded dll')
            dll = decrypt_resource(cipher)

            with open('output/explorer_dll.bin', 'wb') as f:
                f.write(dll)

            res_base_config = extract_resource('output/explorer_dll.bin', '308')

            if res_base_config:
                print('[+] Extracting base configuration')
                base_config = decrypt_resource(res_base_config)

                with open('output/config.txt', 'wb') as f:
                    f.write(base_config)

            res_script = extract_resource('output/explorer_dll.bin', '310')

            if res_script:
                print('[+] Extracting embedded script')
                script = decrypt_resource(res_script)

                with open('output/script.txt', 'wb') as f:
                    f.write(script)

            res_c2cs = extract_resource('output/explorer_dll.bin', '311')

            if res_c2cs:
                print('[+] Extracting C2C server list')
                c2cs = decrypt_resource(res_c2cs)

                with open('output/c2c.txt', 'wb') as f:
                    f.write(c2cs)
        else:
            print('The provided file is not a Qakbot binary or it is broken')
    except FileNotFoundError:
        print('Provided filename does not exists')