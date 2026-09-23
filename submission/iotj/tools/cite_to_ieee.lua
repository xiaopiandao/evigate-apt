-- Preserve Pandoc's citation parsing while emitting IEEE/BibTeX citation commands.
function Cite(element)
  local keys = {}
  for _, citation in ipairs(element.citations) do
    table.insert(keys, citation.id)
  end
  return pandoc.RawInline("latex", "\\cite{" .. table.concat(keys, ",") .. "}")
end
