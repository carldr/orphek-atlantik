// Locate each marker string in memory, then decompile functions referencing it.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.HashSet;
import java.util.Set;

public class DumpFns extends GhidraScript {
    public void run() throws Exception {
        String[] markers = getScriptArgs();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<Function> seen = new HashSet<>();
        for (String m : markers) {
            Address sa = find(m);   // search program memory for the literal string
            println("MARKER '" + m + "' -> " + sa);
            if (sa == null) continue;
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(sa);
            int nref = 0;
            for (Reference r : ri) {
                nref++;
                Function f = getFunctionContaining(r.getFromAddress());
                println("  ref from " + r.getFromAddress() + " in " + (f == null ? "?" : f.getName()));
                if (f != null && seen.add(f)) {
                    println("========== FUNC " + f.getName() + " @" + f.getEntryPoint() + " ==========");
                    DecompileResults res = dec.decompileFunction(f, 90, monitor);
                    if (res != null && res.decompileCompleted())
                        println(res.getDecompiledFunction().getC());
                    else println("[decompile failed]");
                }
            }
            if (nref == 0) println("  (no refs to string address; MIPS lui/addiu may not be linked)");
        }
        dec.dispose();
    }
}
