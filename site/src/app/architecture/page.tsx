import DocPage from "@/components/DocPage";
import { readDoc } from "@/lib/content";
import { loadArch } from "@/lib/parse-arch";
import { chapter } from "@/lib/site";

export const metadata = { title: "Architecture" };

const CH = chapter("/architecture/");

export default function ArchitecturePage() {
  const md = readDoc("ArchitectureV2.md");
  const arch = loadArch();
  return (
    <DocPage file="ArchitectureV2.md" md={md} title="Architecture" chapter={CH.n} left={[`Revision ${arch.revision}`]}>
      <p>
        The logical decomposition of the Gateway into {arch.subsystems.length} subsystems and {arch.elements.length}{" "}
        elements, with {arch.functions.length} functions, {arch.external.length + arch.internal.length} interfaces and{" "}
        {arch.stores.length} data stores, rendered from the architecture document dated {arch.date}.
      </p>
    </DocPage>
  );
}
