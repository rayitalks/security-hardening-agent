"""Bounded PDF text and concealment indicators; called in the optional audit runtime."""
import json
import sys
from pypdf import PdfReader
from pypdf.generic import ContentStream

def inspect(path):
    reader=PdfReader(path);texts=[];hidden=[];white=[];chars=0
    for index,page in enumerate(reader.pages[:100]):
        text=(page.extract_text() or '')[:max(0,1000000-chars)];texts.append(text);chars+=len(text)
        try:
            stream=ContentStream(page.get_contents(),reader);color=(0,0,0);mode=0;stack=[]
            for values,op in stream.operations[:100000]:
                if op==b'q':stack.append((color,mode))
                elif op==b'Q' and stack:color,mode=stack.pop()
                elif op==b'rg':color=tuple(float(v) for v in values[:3])
                elif op==b'g':color=(float(values[0]),)*3
                elif op==b'Tr':mode=int(values[0])
                elif op in (b'Tj',b'TJ',b"'",b'"'):
                    if mode==3:hidden.append(index+1)
                    if len(color)==3 and all(v>=.95 for v in color):white.append(index+1)
        except Exception:pass
        if chars>=1000000:break
    return {'text':'\n'.join(texts),'hiddenTextPages':sorted(set(hidden)),'whiteTextPages':sorted(set(white)),
            'pagesExamined':len(texts),'pageCount':len(reader.pages),
            'limitations':'White text is an indicator against an assumed light page; actual backgrounds, forms, transparency, OCR and complex clipping are not fully rendered.'}

if __name__=='__main__':
    print(json.dumps(inspect(sys.argv[1]),ensure_ascii=True))
