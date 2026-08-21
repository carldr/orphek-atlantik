// Decompile the function at a given address (script arg, e.g. 0x407abc) and list
// its callers and callees. Usage: -postScript DumpFnAt.java 0x407abc [0x...]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class DumpFnAt extends GhidraScript {
    public void run() throws Exception {
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        for (String a : getScriptArgs()) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function f = getFunctionContaining(addr);
            if (f == null) { println("no function at " + a); continue; }
            println("========== " + f.getName() + " @" + f.getEntryPoint() + " ==========");
            println("CALLERS:");
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            for (Reference r : ri) {
                Function c = getFunctionContaining(r.getFromAddress());
                println("  <- " + (c != null ? c.getName() + " @" + c.getEntryPoint() : r.getFromAddress()));
            }
            println("CALLEES: " + f.getCalledFunctions(monitor));
            DecompileResults res = dec.decompileFunction(f, 90, monitor);
            if (res != null && res.decompileCompleted())
                println(res.getDecompiledFunction().getC());
            else println("[decompile failed]");
        }
        dec.dispose();
    }
}
