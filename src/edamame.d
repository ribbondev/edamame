import std.stdio;
import pe;

void main() {
  pe_ctx_t ctx;
  auto e = pe_load_file(&ctx, "tests/test_applications/hello-world.exe");
  if (e != pe_err_e.LIBPE_E_OK) {
    writeln("Failed to load file:", e);
    return;
  }
  e = pe_parse(&ctx);
  if (e != pe_err_e.LIBPE_E_OK) {
    writeln("Unable to parse file");
    return;
  }
  if (!pe_is_pe(&ctx)) {
    writeln("Not a PE file");
    return;
  }
  writeln("Valid PE file");
  writeln("Entry point: ", ctx.pe.entrypoint);
}
