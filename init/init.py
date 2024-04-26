import sys
import argparse

from seashell.core.ipa import IPA
from seashell.core.hook import Hook
from seashell.core.console import Console


def cli() -> None:
    """ SeaShell Framework command-line interface.

    :return None: None
    """

    description = ("SeaShell Framework is an iOS post-exploitation framework that enables you "
                   "to access the device remotely, control it and extract sensitive information.")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        '--ipa',
        dest='ipa',
        action='store_true',
        help='Provide IPA to patch.',
    )
    parser.add_argument(
        '-i',
        '--in',
        dest='input',
        help='Provide IPA to patch. (do not use to build new one)'
    )
    parser.add_argument(
        '-o',
        '--out',
        dest='output',
        help='Where to save new IPA. (does not work with -i)'
    )
    parser.add_argument(
        '--name',
        dest='name',
        help='Set name for new IPA. (does not work with -i)'
    )
    parser.add_argument(
        '--bundle',
        dest='bundle',
        help='Set bundle ID for new IPA. (does not work with -i)'
    )
    parser.add_argument(
        '--icon',
        dest='icon',
        help='Set icon for new IPA. (does not work with -i)'
    )
    parser.add_argument(
        '--host',
        dest='host',
        help='Host to connect to.'
    )
    parser.add_argument(
        '--port',
        dest='port',
        type=int,
        help='Port to connect to.'
    )
    args = parser.parse_args()

    if args.ipa and args.port and args.host:
        if args.input:
            hook = Hook(args.host, args.port)
            hook.patch_ipa(args.input)

        else:
            ipa = IPA(args.host, args.port)
            ipa.set_name(args.name, args.bundle)

            if args.output:
                ipa.generate(args.output)
            else:
                ipa.generate('.')

        sys.exit(0)

    console = Console()
    console.console()
