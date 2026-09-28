import random
random.seed(7)
parts=['<?xml version="1.0"?>\n<big>']
for i in range(3000):
    parts.append(f'<e{i} a{i%300}="v{i%100}" k="{i%70}">t{i%500}</e{i}>')
parts.append('</big>')
open('xml/indexes.xml','w').write(''.join(parts))
with open('xml/large.xml','w') as f:
    f.write('<?xml version="1.0"?>\n<orders xmlns="urn:orders">')
    for i in range(60000):
        f.write(f'<order id="{i}" status="{["new","shipped","paid"][i%3]}"><customer>Kunde {i%977}</customer><amount>{i*13%10000}.{i%100:02d}</amount><comment>{"x"*(i%400)}</comment></order>')
    f.write('</orders>')
