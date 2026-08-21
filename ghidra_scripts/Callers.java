// Decompile callers of a named (external) function. Usage: -postScript Callers.java pthread_create
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
public class Callers extends GhidraScript {
  public void run() throws Exception {
    String name = getScriptArgs()[0];
    DecompInterface dec = new DecompInterface(); dec.openProgram(currentProgram);
    java.util.HashSet<Function> seen = new java.util.HashSet<>();
    for (Symbol s : currentProgram.getSymbolTable().getSymbols(name)) {
      println("SYMBOL " + name + " @" + s.getAddress());
      for (Reference r : currentProgram.getReferenceManager().getReferencesTo(s.getAddress())) {
        Function f = getFunctionContaining(r.getFromAddress());
        if (f != null && seen.add(f)) {
          println("===== caller " + f.getName() + " @" + f.getEntryPoint() + " =====");
          DecompileResults res = dec.decompileFunction(f, 60, monitor);
          if (res != null && res.decompileCompleted()) println(res.getDecompiledFunction().getC());
        }
      }
    }
    dec.dispose();
  }
}
