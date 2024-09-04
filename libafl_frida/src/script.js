"use strict";
class LibAfl {
    static testFunction(message) {
        const buf = Memory.allocUtf8String(message);
        LibAfl.jsApiTestFunction(buf);
    }

    static jsApiGetFunction(name, retType, argTypes) {
        const addr = Module.getExportByName(null, name);
        return new NativeFunction(addr, retType, argTypes);
    }
};
LibAfl.jsApiTestFunction = LibAfl.jsApiGetFunction("test_function", "void", ["pointer"]);
