import sys

from jinja2 import Template

def gen_mask(end):
    mask = 0
    for j in range(16):
        # current bit is 0 indicating passive nibble
        if end % 2 == 0:
            mask |= 15 << (4*j)
        end >>= 1
    return '{0:#x}'.format(mask)

def gen_logic(diff):
    lines = []
    for i in range(16):
        if diff % 2 == 1:
            lines.append("(a >> {0} & 0xF) != (b >> {0} & 0xF) &&".format(4*i))

        diff >>= 1

    if len(lines) == 0:
        return "return 1;"

    lines[-1] = lines[-1][:-3]
    combined = "\n".join(["        {}".format(line) for line in lines])
    return "    return (\n{}\n    );".format(combined)

def gen_passive_logic(start):
    hex_str = "{:04X}".format(start)
    lines = []
    total_bits = 64 - 4 * bin(start).count("1")
    num_bits = total_bits
    for i in range(4):
        line = "pt[{}] = ".format(i)

        c = hex_str[i]
        if c == '0':
            line += "i >> {} & 0xFFFF".format(num_bits - 16)
            num_bits -= 16
        elif c == '1':
            line += "(i >> {} & 0xFFF) << 4".format(num_bits - 12)
            num_bits -= 12
        elif c == '2':
            line += "((i >> {} & 0xFF) << 8) | (i >> {} & 0xF)".format(num_bits - 8, num_bits - 12)
            num_bits -= 12
        elif c == '3':
            line += "i >> {} & 0xFF << 8".format(num_bits - 8)
            num_bits -= 8
        elif c == '4':
            line += "((i >> {} & 0xF) << 12) | (i >> {} & 0xFF)".format(num_bits - 4, num_bits - 12)
            num_bits -= 12
        elif c == '5':
            line += "((i >> {} & 0xF) << 12) | ((i >> {} & 0xF) << 4)".format(num_bits - 4, num_bits - 8)
            num_bits -= 8
        elif c == '6':
            line += "((i >> {} & 0xF) << 12) | (i >> {} & 0xF)".format(num_bits - 4, num_bits - 8)
            num_bits -= 8
        elif c == '7':
            line += "(i >> {} & 0xF) << 12".format(num_bits - 4)
            num_bits -= 4
        elif c == '8':
            line += "i >> {} & 0xFFF".format(num_bits - 12)
            num_bits -= 12
        elif c == '9':
            line += "(i >> {} & 0xFF) << 4".format(num_bits - 8)
            num_bits -= 8
        elif c == '10':
            line += "((i >> {} & 0xF) << 8) | (i >> {} & 0xF)".format(num_bits - 4, num_bits - 8)
            num_bits -= 8
        elif c == '11':
            line += "(i >> {} & 0xF) << 8".format(num_bits - 4)
            num_bits -= 4
        elif c == '12':
            line += "i >> {} & 0xFF".format(num_bits - 8)
            num_bits -= 8
        elif c == '13':
            line += "(i >> {} & 0xF) << 4".format(num_bits - 4)
            num_bits -= 4
        elif c == '14':
            line += "i >> {} & 0xF".format(num_bits - 4)
            num_bits -= 4
        elif c == '15':
            line += "0"

        line += ";"
        lines.append(line)

    return "\n".join(["    {}".format(line) for line in lines])

def gen_start_active_logic(start):
    hex_str = "{:4X}".format(start).replace(" ", "0")
    lines = []
    num_active = bin(start).count("1")
    num_vars = num_active

    lines.append("uint16_t {};".format(
        ", ".join(
            "i{}".format(i) for i in range(num_active)
        )
    ))
    for i in range(num_active):
        lines.append("for (i{0} = 0; i{0} < 16; ++i{0})".format(i) + " {")

    for i in range(4):
        c = int(hex_str[i])

        if c == 0:
            continue

        tmp = c
        mask = 0
        for j in range(4):
            # current bit is 0 indicating passive nibble
            if tmp % 2 == 0:
                mask |= 15 << (4*j)
            tmp >>= 1
        line = 'pt[{}] &= {:#x};'.format(i, mask)
        lines.append(line)

        line = "pt[{}] |= ".format(i)
        j = num_active - num_vars
        if c == 1:
            line += "i{}".format(j)
            num_vars -= 1
        elif c == 2:
            line += "i{} << 4".format(j)
            num_vars -= 1
        elif c == 3:
            line += "(i{} << 4) | i{}".format(j, j+1)
            num_vars -= 2
        elif c == 4:
            line += "i{} << 8".format(j)
            num_vars -= 1
        elif c == 5:
            line += "(i{} << 8) | i{}".format(j, j+1)
            num_vars -= 2
        elif c == 6:
            line += "(i{} << 8) | (i{} << 4)".format(j, j+1)
            num_vars -= 2
        elif c == 7:
            line += "(i{} << 8) | (i{} << 4) | i{}".format(j, j+1, j+2)
            num_vars -= 3
        elif c == 8:
            line += "i{} << 12".format(j)
            num_vars -= 1
        elif c == 9:
            line += "(i{} << 12) | i{}".format(j, j+1)
            num_vars -= 2
        elif c == 10:
            line += "(i{} << 12) | (i{} << 4)".format(j, j+1)
            num_vars -= 2
        elif c == 11:
            line += "(i{} << 12) | (i{} << 4) | i{}".format(j, j+1, j+2)
            num_vars -= 3
        elif c == 12:
            line += "(i{} << 12) | (i{} << 8)".format(j, j+1)
            num_vars -= 2
        elif c == 13:
            line += "(i{} << 12) | (i{} << 8) | i{}".format(j, j+1, j+2)
            num_vars -= 3
        elif c == 14:
            line += "(i{} << 12) | (i{} << 8) | (i{} << 4)".format(j, j+1, j+2)
            num_vars -= 3
        elif c == 15:
            line += "(i{} << 12) | (i{} << 8) | (i{} << 4) | i{}".format(j, j+1, j+2, j+3)
            num_vars -= 4
        line += ";"
        lines.append(line)

    return "\n".join(["    {}".format(line) for line in lines])

def gen_id_active_logic(start):
    hex_str = "{:4X}".format(start)
    num_active = bin(start).count("1")
    return(" | ".join(
            "i{} << {}".format(i, 4 * (num_active - i - 1)) for i in range(num_active)
        )
    )

def gen_end_active_logic(start):
    hex_str = "{:4X}".format(start)
    num_active = bin(start).count("1")
    lines = []
    for i in range(num_active):
        lines.append("}")
    return "\n".join(["    {}".format(line) for line in lines])

def main():
    if len(sys.argv) < 3:
        print("usage: {} [start] [end0] [end1] [end2] ...".format(sys.argv[0]))
        sys.exit(1)

    start = int(sys.argv[1])
    ends = [int(i) for i in sys.argv[2:]]

    masks = {}
    logics = {}
    logics[start] = gen_logic(start)
    for end in ends:
        masks[end] = gen_mask(end)
        logics[end] = gen_logic(end)

    passive_logic = gen_passive_logic(start)
    start_active_logic = gen_start_active_logic(start)
    id_active_logic = gen_id_active_logic(start)
    end_active_logic = gen_end_active_logic(start)

    with open('gen_pairs.c.jinja') as f:
        tmpl = Template(f.read())

    info = {
        "start": start,
        "ends": ends,
        "num_active": bin(start).count("1"),
        "masks": masks,
        "logics": logics,
        "passive_logic": passive_logic,
        "start_active_logic": start_active_logic,
        "id_active_logic": id_active_logic,
        "end_active_logic": end_active_logic
    }
    print(tmpl.render(**info))

if __name__ == "__main__":
    main()

