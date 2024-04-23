# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json
import socket
import os, os.path

import falcon
from hio import help
from hio.base import doing
from hio.core import http
from hio.core.unixing import serving
from hio.help import decking

from keri import kering
from keri.app import habbing
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


class HttpEnd:
    """
    HTTP handler that accepts and KERI events POSTed as the body of a request with all attachments to
    the message as a CESR attachment HTTP header.  KEL Messages are processed and added to the database
    of the provided Habitat.

    This also handles `req`, `exn` and `tel` messages that respond with a KEL replay.
    """

    TimeoutQNF = 30
    TimeoutMBX = 5

    def __init__(self, psr, cues):
        """
        Create the KEL HTTP server from the Habitat with an optional Falcon App to
        register the routes with.

        Parameters
             rxbs (bytearray): output queue of bytes for message processing
             mbx (Mailboxer): Mailbox storage
             qrycues (Deck): inbound qry response queues

        """
        self.psr = psr
        self.cues = cues


    def on_put(self, req, rep):
        """
        Handles PUT for KERI mbx event messages.

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        ---
        summary:  Accept KERI events with attachment headers and parse
        description:  Accept KERI events with attachment headers and parse.
        tags:
           - Events
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 description: KERI event message
        responses:
           200:
              description: Mailbox query response for server sent events
           204:
              description: KEL or EXN event accepted.
        """
        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")

        self.psr.parseOne(ims=req.bounded_stream.read())

        if self.cues:
            msg = self.cues.popleft()
            rep.data = json.dumps(msg).encode("utf-8")
            rep.set_header('Content-Type', "application/json")
            rep.status = falcon.HTTP_200
        else:
            rep.status = falcon.HTTP_204


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

            self.cues.append(identifiers)
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
            habbing.Habery(name=name, base=self.base, bran=passcode, free=True)
            msg = dict(status=falcon.HTTP_200, body={})
        except (kering.AuthError, ValueError) as e:
            msg = dict(status=falcon.HTTP_400, body=str(e))

        self.cues.append(msg)


def handler(args):
    """ Command line list handler

    """
    kwa = dict(args=args)
    app = falcon.App(cors_enable=True)
    hby = existing.setupHby(name="listener", base=args.base, bran=args.bran)
    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer

    cues = decking.Deck()
    loadHandlers(hby, cues)

    httpEnd = HttpEnd(psr=hby.psr, cues=cues)
    app.add_route("/", httpEnd)

    if os.path.exists("/tmp/keripy_kli.s"):
        os.remove("/tmp/keripy_kli.s")

    servant = serving.Server(path="/tmp/keripy_kli.s",
                             bufsize=8069)
    server = http.Server(app=app, servant=servant)
    httpServerDoer = http.ServerDoer(server=server)

    return [doing.doify(listen, **kwa), httpServerDoer, hbyDoer]


def listen(tymth, tock=0.0, **opts):
    _ = (yield tock)
    args = opts["args"]
    base = args.base
    bran = args.bran

    with existing.existingHby(name="listener", base=base, bran=bran) as hby:

        # cues = decking.Deck()
        # loadHandlers(hby, cues)
        #
        # if os.path.exists("/tmp/keripy_kli.s"):
        #     os.remove("/tmp/keripy_kli.s")
        #
        # server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # server.bind("/tmp/keripy_kli.s")

        while True:
            yield tock
            # server.listen(1)
            # conn, addr = server.accept()
            # datagram = conn.recv(1024)
            # hby.psr.parseOne(bytes(datagram))

            # while not cues:
            #     yield tock
            #
            # msg = cues.popleft()
            # data = json.dumps(msg).encode("utf-8")
            # print(data)

            # conn.sendto(data, addr)

