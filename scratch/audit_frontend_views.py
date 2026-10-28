import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

pos = text.find('id="history-table"')
if pos != -1:
    start = max(0, pos - 1500)
    print(text[start:pos])
