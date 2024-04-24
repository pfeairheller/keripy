# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import os
import os.path

import falcon
from hio import help
from hio.core.uxd import Server, ServerDoer
from hio.help import decking

from keri import kering
from keri.app import habbing, directing
from keri.app.cli.common import existing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Run Unix domain sockets server listening for browser support')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def loadHandlers(hby, cues):
    ids = IdentifiersHandler(cues=cues, base=hby.base)
    hby.exc.addHandler(ids)
    unlock = UnlockHandler(cues=cues, base=hby.base)
    hby.exc.addHandler(unlock)


class IdentifiersHandler:
    """  Handle challenge response peer to peer `exn` message """

    resource = "/identifiers"

    def __init__(self, cues, base):
        """ Initialize peer to peer challenge response messsage """

        self.cues = cues
        self.base = base
        super(IdentifiersHandler, self).__init__()

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of Challenge response messages

        Parameters:
            serder (Serder): Serder of the exn challenge response message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        payload = serder.ked['a']
        name = payload["name"]
        passcode = payload["passcode"] if "passcode" in payload else None

        try:
            hby = habbing.Habery(name=name, base=self.base, bran=passcode)

            identifiers = []
            for hab in hby.habs.values():
                msg = dict(name=hab.name, prefix=hab.pre)
                identifiers.append(msg)

            hby.close()
            self.cues.append(dict(status=falcon.HTTP_200, body=identifiers))
        except (kering.AuthError, ValueError) as e:
            msg = dict(status=falcon.HTTP_400, body=str(e))
            self.cues.append(msg)


class UnlockHandler:
    """  Handle challenge response peer to peer `exn` message """

    resource = "/unlock"

    def __init__(self, cues, base):
        """ Initialize peer to peer challenge response messsage """

        self.cues = cues
        self.base = base
        super(UnlockHandler, self).__init__()

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of Challenge response messages

        Parameters:
            serder (Serder): Serder of the exn challenge response message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        payload = serder.ked['a']
        name = payload["name"]
        passcode = payload["passcode"] if "passcode" in payload else None

        try:
            hby = habbing.Habery(name=name, base=self.base, bran=passcode, free=True)
            msg = dict(status=falcon.HTTP_200, body={})
            hby.close()

        except (kering.AuthError, ValueError) as e:
            msg = dict(status=falcon.HTTP_400, body=str(e))

        self.cues.append(msg)


def handler(args):
    """ Command line list handler

    """
    hby = existing.setupHby(name="listener", base=args.base, bran=args.bran)
    hab = hby.habByName("listener")

    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer

    cues = decking.Deck()
    loadHandlers(hby, cues)

    if os.path.exists("/tmp/keripy_kli.s"):
        os.remove("/tmp/keripy_kli.s")

    server = Server(path="/tmp/keripy_kli.s",
                            bufsize=8069)
    serverDoer = ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server, exchanger=hby.exc, cues=cues)

    return [directant, serverDoer, hbyDoer]
