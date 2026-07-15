/**
 * Source: https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 * Hooks libc connect() to redirect all outgoing TCP connections to the proxy,
 * bypassing Flutter's deliberate ignoring of the Android system proxy setting.
 * Must be loaded AFTER config.js (depends on PROXY_HOST, PROXY_PORT, etc.)
 */

(() => {
  const PROXY_HOST_IPv4_BYTES = PROXY_HOST.split(".").map((part) =>
    parseInt(part, 10),
  );
  const IPv6_MAPPING_PREFIX_BYTES = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff,
  ];
  const PROXY_HOST_IPv6_BYTES = IPv6_MAPPING_PREFIX_BYTES.concat(
    PROXY_HOST_IPv4_BYTES,
  );

  const F_GETFL = 3;
  const F_SETFL = 4;
  const O_NONBLOCK = Process.platform === "darwin" ? 4 : 2048;

  let fcntl, send, recv, conn;
  try {
    const systemModule =
      Process.findModuleByName("libc.so") ??
      Process.findModuleByName("libc.so.6") ??
      Process.findModuleByName("libsystem_c.dylib");

    if (!systemModule) throw new Error("Could not find libc or libsystem_c");

    fcntl = new NativeFunction(systemModule.getExportByName("fcntl"), "int", [
      "int",
      "int",
      "int",
    ]);
    send = new NativeFunction(systemModule.getExportByName("send"), "ssize_t", [
      "int",
      "pointer",
      "size_t",
      "int",
    ]);
    recv = new NativeFunction(systemModule.getExportByName("recv"), "ssize_t", [
      "int",
      "pointer",
      "size_t",
      "int",
    ]);
    conn = systemModule.getExportByName("connect");
  } catch (e) {
    console.error("Failed to set up native hooks:", e.message);
    return;
  }

  Interceptor.attach(conn, {
    onEnter(args) {
      const fd = (this.sockFd = args[0].toInt32());
      const sockType = Socket.type(fd);

      const addrPtr = ptr(args[1]);
      const addrLen = args[2].toInt32();
      const addrData = addrPtr.readByteArray(addrLen);

      const isTCP = sockType === "tcp" || sockType === "tcp6";
      const isUDP = sockType === "udp" || sockType === "udp6";
      const isIPv6 = sockType === "tcp6" || sockType === "udp6";

      if (isTCP || isUDP) {
        const portAddrBytes = new DataView(addrData.slice(2, 4));
        const port = portAddrBytes.getUint16(0, false);

        const shouldBeIgnored = IGNORED_NON_HTTP_PORTS.includes(port);
        const shouldBeBlocked =
          BLOCK_HTTP3 && !shouldBeIgnored && isUDP && port === 443;
        const shouldBeIntercepted =
          isTCP && !shouldBeIgnored && !shouldBeBlocked;

        const hostBytes = isIPv6
          ? new Uint8Array(addrData.slice(8, 8 + 16))
          : new Uint8Array(addrData.slice(4, 4 + 4));

        const isAlreadyProxy =
          port === PROXY_PORT &&
          areArraysEqual(
            hostBytes,
            isIPv6 ? PROXY_HOST_IPv6_BYTES : PROXY_HOST_IPv4_BYTES,
          );
        if (isAlreadyProxy) return;

        if (shouldBeBlocked) {
          if (isIPv6) {
            for (let i = 0; i < 16; i++) addrPtr.add(8 + i).writeU8(0);
          } else {
            addrPtr.add(4).writeU32(0);
          }
          this.state = "Blocked";
        } else if (shouldBeIntercepted) {
          this.state = "intercepting";

          if (PROXY_SUPPORTS_SOCKS5) {
            this.originalDestination = { host: hostBytes, port, isIPv6 };
            this.originalFlags = fcntl(this.sockFd, F_GETFL, 0);
            this.isNonBlocking = (this.originalFlags & O_NONBLOCK) !== 0;
            if (this.isNonBlocking)
              fcntl(this.sockFd, F_SETFL, this.originalFlags & ~O_NONBLOCK);
          }

          console.log(
            `Intercepting ${sockType} -> ${getReadableAddress(hostBytes, isIPv6)}:${port}`,
          );

          portAddrBytes.setUint16(0, PROXY_PORT, false);
          addrPtr.add(2).writeByteArray(portAddrBytes.buffer);

          if (isIPv6) {
            addrPtr.add(8).writeByteArray(PROXY_HOST_IPv6_BYTES);
          } else {
            addrPtr.add(4).writeByteArray(PROXY_HOST_IPv4_BYTES);
          }
        } else {
          this.state = "ignored";
        }
      } else {
        this.state = "ignored";
      }
    },
    onLeave(retval) {
      if (this.state === "ignored") return;

      if (this.state === "intercepting" && PROXY_SUPPORTS_SOCKS5) {
        const connectSuccess = retval.toInt32() === 0;
        let handshakeSuccess = false;
        const { host, port, isIPv6 } = this.originalDestination;
        if (connectSuccess) {
          handshakeSuccess = performSocksHandshake(
            this.sockFd,
            host,
            port,
            isIPv6,
          );
        }
        if (this.isNonBlocking) fcntl(this.sockFd, F_SETFL, this.originalFlags);
        retval.replace(handshakeSuccess ? 0 : -1);
      }
    },
  });

  console.log(
    `[+] native-connect-hook: redirecting all TCP -> ${PROXY_HOST}:${PROXY_PORT}`,
  );

  const getReadableAddress = (hostBytes, isIPv6) => {
    if (!isIPv6) return [...hostBytes].map((x) => x.toString()).join(".");
    if (
      hostBytes.slice(0, 10).every((b) => b === 0) &&
      hostBytes.slice(10, 12).every((b) => b === 255)
    ) {
      return (
        "::ffff:" + [...hostBytes.slice(12)].map((x) => x.toString()).join(".")
      );
    }
    return `[${[...hostBytes].map((x) => x.toString(16)).join(":")}]`;
  };

  const areArraysEqual = (a, b) =>
    a.length === b.length && a.every((x, i) => b[i] === x);

  function performSocksHandshake(sockfd, targetHostBytes, targetPort, isIPv6) {
    const hello = Memory.alloc(3).writeByteArray([0x05, 0x01, 0x00]);
    if (send(sockfd, hello, 3, 0) < 0) return false;
    const response = Memory.alloc(2);
    if (recv(sockfd, response, 2, 0) < 0) return false;
    if (response.readU8() !== 0x05 || response.add(1).readU8() !== 0x00)
      return false;
    let req = [0x05, 0x01, 0x00, isIPv6 ? 0x04 : 0x01];
    req.push(...targetHostBytes, (targetPort >> 8) & 0xff, targetPort & 0xff);
    const reqBuf = Memory.alloc(req.length).writeByteArray(req);
    if (send(sockfd, reqBuf, req.length, 0) < 0) return false;
    const replyHeader = Memory.alloc(4);
    if (recv(sockfd, replyHeader, 4, 0) < 0) return false;
    if (replyHeader.add(1).readU8() !== 0x00) return false;
    const atyp = replyHeader.add(3).readU8();
    const rem = atyp === 0x01 ? 6 : atyp === 0x04 ? 18 : 0;
    if (rem > 0) recv(sockfd, Memory.alloc(rem), rem, 0);
    return true;
  }
})();
