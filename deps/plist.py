app_name = 'Mussel'
bundle_id = 'com.entysec.mussel'
binary_name = 'main'


def generate_plist(host, port):
    return {
        'CFBundleDevelopmentRegion': 'en',
        'CFBundleDisplayName': app_name,
        'CFBundleExecutable': binary_name,
        'CFBundleIdentifier': bundle_id,
        'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundleName': app_name,
        'CFBundlePackageType': 'APPL',
        'CFBundleShortVersionString': '1.0.0',
        'CFBundleSignature': String().base64_string(f'{host}:{str(port)}', decode=True),
        'CFBundleVersion': '1',
        'LSRequiresIPhoneOS': True,
        'UISupportedInterfaceOrientations': [
            'UIInterfaceOrientationPortrait',
            'UIInterfaceOrientationPortraitUpsideDown',
            'UIInterfaceOrientationLandscapeLeft',
            'UIInterfaceOrientationLandscapeRight'
        ]
    }


def main():
    if len(sys.argv) < 4:
        print(f'Usage: {sys.argv[0]} <host> <port> <path>')
        return

    with open(sys.argv[3], 'wb') as f:
        plistlib.dump(generate_plist(sys.argv[1], sys.argv[2]), f)


if __name__ == "__main__":
    main()
