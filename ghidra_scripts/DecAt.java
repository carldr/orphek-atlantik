import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
public class DecAt extends GhidraScript {
  public void run() throws Exception {
    DecompInterface dec = new DecompInterface(); dec.openProgram(currentProgram);
    for (String a : getScriptArgs()) {
      Address addr = currentProgram.getAddressFactory().getAddress(a);
      Function f = getFunctionContaining(addr);
      if (f == null) f = createFunction(addr, null);
      if (f == null) { println("no func at "+a); continue; }
      println("========== "+f.getName()+" @"+f.getEntryPoint()+" ==========");
      DecompileResults res = dec.decompileFunction(f, 120, monitor);
      if (res!=null && res.decompileCompleted()) println(res.getDecompiledFunction().getC());
      else println("[decompile failed]");
    }
    dec.dispose();
  }
}
