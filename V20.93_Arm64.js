function main() {
  const base = Module.findBaseAddress("libg.so");
  const RuntimePatcher = {
    nop: function (addr) {
      Memory.patchCode(addr, Process.pageSize, function (code) {
        var writer = new Arm64Writer(code, {
          pc: addr,
        });

        writer.putNop();
        writer.flush();
      });
    },
    ret: function (addr) {
      Memory.patchCode(addr, Process.pageSize, function (code) {
        var writer = new Arm64Writer(code, {
          pc: addr,
        });

        writer.putRet();
        writer.flush();
      });
    },
    replace: function (address, newInsn) {
      Memory.protect(address, newInsn.length, "rwx");
      address.writeByteArray(newInsn);
      Memory.protect(address, newInsn.length, "rx");
    },
    jmp: function (addr, target) {
      Memory.patchCode(addr, Process.pageSize, function (code) {
        var writer = new Arm64Writer(code, {
          pc: addr,
        });

        writer.putBranchAddress(target);
        writer.flush();
      });
    },
  };
  const inet_addr = new NativeFunction(
    Module.findExportByName("libc.so", "inet_addr"),
    "uint32",
    ["pointer"]
  );
  const ntohs = new NativeFunction(
    Module.findExportByName("libc.so", "ntohs"),
    "uint16",
    ["uint16"]
  );
  const ClientSecretKey = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]; //your client secret (just generate it)
  const host = "192.168.0.180";

  Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function (args) {
      if (ntohs(Memory.readU16(args[1].add(2))) === 9339) {
        var str = Memory.allocUtf8String(host);
        Memory.writeInt(args[1].add(4), inet_addr(str)); //redirect host
      }
    },
  });

  //client secret patcher
  Interceptor.attach(base.add(0x3be018), {
    onEnter(args) {
      this.buffer = args[0];
    },
    onLeave(retval) {
      this.buffer.writeByteArray(ClientSecretKey);
    },
  });

  /* misc */

  // enable offline battles
  Interceptor.attach(base.add(0x112358), {
    onEnter(a) {
      a[3] = ptr(3);
    },
  });
  // enable lobby info
  Interceptor.attach(base.add(0x14a7c8), {
    onLeave(r) {
      r.replace(0); //LogicVersion::isProd (vrode)
    },
  });

  // arxan killer
  RuntimePatcher.jmp(base.add(0x337668), base.add(0x338400));
  RuntimePatcher.jmp(base.add(0x399724), base.add(0x39a488));
}

rpc.exports.init = function () {
  main();
};
