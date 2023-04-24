#!/usr/bin/env python3

##################################################
# !!! Research-grade code. Feel free to fix. !!! #
##################################################

import sys, json, base64, pprint, svgwrite, zlib

#DEFAULT_CLR = """
#[DISASM]
#000000	 //
#ff0000	 //Default color
#ff0000	 //Regular comment
#808080	 //Repeatable comment
#808080	 //Automatic comment
#800000	 //Instruction
#800000	 //Dummy Data Name
#ff0000	 //Regular Data Name
#ff0000	 //Demangled Name
#800000	 //Punctuation
#008000	 //Char constant in instruction
#00ff00	 //String constant in instruction
#008000	 //Numeric constant in instruction
#0080ff	 //Void operand
#008000	 //Code reference
#ff8080	 //Data reference
#0000ff	 //Code reference to tail byte
#008080	 //Data reference to tail byte
#010101	 //Error or problem
#c0c0c0	 //Line prefix
#ff0000	 //Binary line prefix bytes
#ff0000	 //Extra line
#ff0000	 //Alternative operand
#808080	 //Hidden name
#ff8080	 //Library function name
#008000	 //Local variable name
#800000	 //Dummy code name
#ff0000	 //Assembler directive
#800080	 //Macro
#008000	 //String constant in data directive
#008000	 //Char constant in data directive
#408000	 //Numeric constant in data directive
#800000	 //Keywords
#800000	 //Register name
#ff00ff	 //Imported name
#008080	 //Segment name
#800000	 //Dummy unknown name
#ff0000	 //Regular code name
#800000	 //Regular unknown name
#ff0000	 //Collapsed line
#000000	 //Max color number
#ffffff	 //Line prefix: library function
#afbbc0	 //Line prefix: regular function
#ffff00	 //Line prefix: instruction
#000000	 //Line prefix: data
#000080	 //Line prefix: unexplored
#808080	 //Line prefix: externs
#008080	 //Line prefix: current item
#ff00ff	 //Line prefix: current line
#000000	 //Punctuation
#ff0000	 //Opcode bytes
#000000	 //Manual operand
#[NAVBAR]
#ffffaa	 //Library function
#e8a200	 //Regular function
#577ab9	 //Instruction
#c0c0c0	 //Data item
#6bb6b6	 //Unexplored
#ffa6ff	 //External symbol
#5b5bff	 //Errors
#000000	 //Gaps
#7fffff	 //Cursor
#00aaff	 //Address
#[DEBUG]
#ffd060	 //Current IP
#ffa0a0	 //Current IP (+ enabled breakpoint)
#408020	 //Current IP (+ disabled breakpoint)
#ffffcc	 //Default background
#0000ff	 //Address (+ enabled breakpoint)
#00ff00	 //Address (+ disabled breakpoint)
#004080	 //Current IP (+ unavailable breakpoint)
#0080ff	 //Address (+ unavailable breakpoint)
#000000	 //Registers
#ff0000	 //Registers (changed)
#800080	 //Registers (edited)
#[ARROW]
#c0c0c0	 //Jump in current function
#0000ff	 //Jump external to function
#000000	 //Jump under the cursor
#008000	 //Jump target
#ff4040	 //Register target
#[GRAPH]
#ffffff	 //Top color
#fff8e0	 //Bottom color
#ffffff	 //Normal title
#f9f9b1	 //Selected title
#cfcfa0	 //Current title
#00ffff	 //Group frame
#000000	 //Node shadow
#ffffcc	 //Highlight color 1
#ccffcc	 //Highlight color 2
#0000ff	 //Foreign node
#ff0000	 //Normal edge
#008000	 //Yes edge
#0000ff	 //No edge
#ff00ff	 //Highlighted edge
#ffff00	 //Current edge
#[MISC]
#000000	 //Message text
#ffffff	 //Message background
#404080	 //Patched bytes
#0080ff	 //Unsaved changes
#[OTHER]
#00ffff	 //Highlight color
#e1ffff	 //Hint color
#[SYNTAX]
#ff0000	0	0	 //Keyword 1
#800080	0	0	 //Keyword 2
#0000ff	0	0	 //Keyword 3
#00008b	0	0	 //String
#006400	0	1	 //Comment
#ff0000	1	0	 //Preprocessor
#8b8b00	1	0	 //Number
#"""

## leet solarized ida theme. wow hacker.
DEFAULT_CLR = """
[DISASM]
000000	 //Instruction
aaaaaa	 //Directive
f3c5ff	 //Macro name
7e6082	 //Register name
666666	 //Other keywords
ffffff	 //Dummy data name
b9ebeb	 //Dummy code name
b9ebeb	 //Dummy unexplored name
bbecff	 //Hidden name
c0c0c0	 //Library function name
00d269	 //Local variable name
00ff00	 //Regular data name
3250d2	 //Regular code name
4646ff	 //Regular unexplored name
7faaff	 //Demangled name
617c7c	 //Segment name
3250d2	 //Imported name
008080	 //Suspicious constant
3734ff	 //Char in instruction
c0c0c0	 //String in instruction
595959	 //Number in instruction
f3c5ff	 //Char in data
ffaaff	 //String in data
00d2ff	 //Number in data
ffff00	 //Code reference
0080ff	 //Data reference
00d2ff	 //Code reference to tail
00d69d	 //Data reference to tail
7e07df	 //Automatic comment
00d269	 //Regular comment
00f379	 //Repeatable comment
3250d2	 //Extra line
ababab	 //Collapsed line
adad73	 //Line prefix: library function
fd5aff	 //Line prefix: regular function
7fffff	 //Line prefix: instruction
00ffaa	 //Line prefix: data
00d2ff	 //Line prefix: unexplored
ffaaff	 //Line prefix: externs
00ffff	 //Line prefix: current item
000000	 //Line prefix: current line
2d2d2d	 //Punctuation
32ade1	 //Opcode bytes
ffff00	 //Manual operand
666666	 //Error
0000aa	 //Default color
41c88e	 //Selected
009d9d	 //Library function
ff55ff	 //Regular function
000000	 //Single instruction
00aaff	 //Data bytes
000000	 //Unexplored byte
[NAVBAR]
ffaa00	 //Library function
00aaff	 //Regular function
000080	 //Instruction
b9ebeb	 //Data item
007878	 //Unexplored
ff00ff	 //External symbol
0000ca	 //Errors
4a4a4a	 //Gaps
00ff80	 //Cursor
0080ff	 //Address
[DEBUG]
ffd060	 //Current IP
32ade1	 //Current IP (Enabled)
408020	 //Current IP (Disabled)
2d2d2d	 //Default Background
000076	 //Address
00ff00	 //Address (Enabled)
004080	 //Address (Disabled)
0080ff	 //Address (Unavailible)
000000	 //Registers
ff0000	 //Registers (Changed)
800080	 //Registers (Edited)
[ARROW]
34466c	 //Jump in current function
dede00	 //Jump external to function
00aaff	 //Jump under the cursor
008000	 //Jump target
ff4040	 //Register target
[GRAPH]
b2b2b2	 //Top color
b2b2b2	 //Bottom color
f5f5f5	 //Normal title
989faa	 //Selected title
54585e	 //Current title
00ffff	 //Group frame
242424	 //Node shadow
003900	 //Highlight color 1
00006d	 //Highlight color 2
0000ff	 //Foreign node
cb4300	 //Normal edge
009100	 //Yes edge
0000bc	 //No edge
ffaaaa	 //Highlighted edge
008ec6	 //Current edge
[MISC]
212121	 //Message text
d4d4d4	 //Message background
404080	 //Patched bytes
0080ff	 //Unsaved changes
00c61a	 //Highlight color
3d3d3d	 //Hint color
"""

def color_format(val):
    t = "".join(["{:02x}".format((val >> i) & 0xff) for i in [0, 8, 16]])
    return "{}".format(t)

def color_by_name(colors, name):
    for c in colors:
        if c[1] == name:
            return "#" + color_format(c[0])
    return None

def color_to_rgb(val):
    return [(val >> i) & 0xff for i in [16, 8, 0]]

def gen_css(colors, j_root):
    res = "\n"
    res += ".background {{ fill: {}; }}\n".format(color_by_name(colors, "bottom_color"))
    res += """
        .block {{
            fill: {};
            stroke: black;
        }}\n""".format(color_by_name(colors, "default_background"),
                              color_by_name(colors, "node_shadow"))
    res += """
        .header {{
            fill: {};
            stroke: black;
        }}\n""".format(color_by_name(colors, "normal_title"))
    res += """
        .disasm {{
            font-family: {};
            font-size: {};
            font-weight: {};
        }}""".format(j_root["font_name"], j_root["font_size"] * 1.5, "bold" if j_root["font_flags"] & 1 else "regular")
    for i in range(0x28):
        res += ".txt_col_{:02x} {{ fill: #{}; }}\n".format(i, color_format(colors[i][0]))

    return res

def decode_disasm_line(line):
    COLOR_BEGIN = 0x01
    COLOR_END = 0x02
    ptr = 0
    res = []
    colstack = []
    text = []
    line = line.strip(b"\x00")
    hidden_chars = 0

    while ptr < len(line):
        # print(ptr, len(line), line[ptr], colstack)
        if line[ptr] == COLOR_BEGIN:
            if line[ptr + 1] == 0x28:
                hidden_chars = 16  ## FIXME: Detect bitness here
            else:
                hidden_addr = False
                colstack.append(line[ptr + 1])
            ptr += 2
        elif line[ptr] == COLOR_END:
            col = colstack.pop()
            assert (col == line[ptr + 1])
            ptr += 2
            res.append((bytes(text).decode("utf-8"), col))
            text = []
        else:
            if hidden_chars == 0:
                text.append(line[ptr])
            else:
                hidden_chars -= 1
            ptr += 1

    return res

def parse_clr(fname):
    try:
        dat = open(fname, 'r').read().splitlines()
    except:
        dat = DEFAULT_CLR.splitlines()  # if file does not exist use the defaults

    res = []

    ign = False
    for i in range(len(dat)):
        if "[SYNTAX]" in dat[i]:
            ign = True  # Skip entries in the syntax section
            continue

        if "[" in dat[i] or "]" in dat[i]:
            ign = False
            continue

        if len(dat[i]) < 8 or ign == True:
            continue

        res.append([int(dat[i].split("\t")[0], 16), dat[i].split("\t")[1]])

        ## Normalize color name
        res[-1][1] = res[-1][1].strip(' /').replace(' ', '_').lower()

    return res

def to_svg(graph, outname):
    def group(classname):
        return dwg.add(dwg.g(class_=classname))

    # to obtain function bytes
    #print(zlib.decompress(base64.b64decode(graph["bytes"])))

    colors = parse_clr(None)
    dwg = svgwrite.Drawing(outname)

    ## Build arrow heads for all edge colors
    arrows = {}
    for e in graph["edges"]:
        col = color_format(e["color"])
        if col in arrows: continue

        head = dwg.marker(size=(8, 10), refX=10, refY=8)  # marker defaults: insert=(0,0)
        head.viewbox(6, 0, 8, 10)
        head.add(dwg.path("M6,0 L10,10 L14,0 L10,3 z", fill="#" + col))
        arrows[col] = head

        dwg.defs.add(head)

    ## Add css style definitions
    dwg.defs.add(dwg.style(gen_css(colors, j_root)))

    ## Build background
    grad_bg = dwg.defs.add(dwg.linearGradient())
    grad_bg.rotate(90)
    grad_bg.add_stop_color(0, color_by_name(colors, "top_color"))
    grad_bg.add_stop_color(1, color_by_name(colors, "bottom_color"))
    dwg.add(dwg.rect(size=('100%', '100%'), fill=grad_bg.get_paint_server()))

    lines = group("line")
    blocks = group("block")
    headers = group("header")
    disasm_block = group("disasm")
    disasm_block.attribs['xml:space'] = 'preserve'

    ## Draw all edges
    for e in graph["edges"]:
        r, g, b = [(e["color"] >> i) & 0xff for i in [0, 8, 16]]
        path = []
        for i in range(len(e["coords"])):
            x0, y0 = map(int, e["coords"][i].split(" "))
            path.append([x0, y0])

        path[-1][1] -= 3 ## HACK: Compensate for arrowhead. Only correct for vertical edges.

        edge = lines.add(dwg.polyline(path, fill='none', stroke_width="1.3", stroke=svgwrite.rgb(r, g, b)))
        edge.set_markers(('none', 'none', arrows[color_format(e["color"])]))

    ## Finally, draw basic blocks
    for b in graph["basic_blocks"]:
        blocks.add(dwg.rect(insert=(b["left"], b["top"]), size=(b["right"] -
                                                                b["left"], b["bottom"] - b["top"])))
        headers.add(dwg.rect(insert=(b["left"], b["top"]), size=(b["right"] -
                                                                 b["left"], 16)))
        y = 32
        text_block = dwg.text("", insert=(b["left"] + 4, b["top"] + 32))
        for l in b["disasm_lines"]:
            parts = decode_disasm_line(base64.b64decode(l["text"]))
            for i, (txt, col) in enumerate(parts):
                text_block.add(dwg.tspan(txt, class_= f"txt_col_{col:02x}", style="background-color: #{color_format(l['bg_color'])}"))
            y += 19.6
            text_block.add(dwg.tspan("", y = [b["top"] + y], x = [b["left"] + 4]))
        disasm_block.add(text_block)

    dwg.save()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("No input file given.")
        sys.exit(-1)

    j_root = json.loads(open(sys.argv[1], 'r').read())

    graph = j_root["functions"][0]
    to_svg(graph, sys.argv[1] + ".svg")
