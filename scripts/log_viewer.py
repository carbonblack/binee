#!/usr/bin/env python
import curses
import curses.textpad
from subprocess import Popen, PIPE
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Run Binee in debug with memory tracking")
    parser.add_argument('--loadlibs', action="store_true", help="Load libs!")
    parser.add_argument('--showdll', action="store_true", help="show dll names on function calls")
    parser.add_argument("--testbin", action="store", default='tests/ConsoleApplication1_x86.exe', help="change default from 'tests/ConsoleApplication1_x86.exe'")
    args = parser.parse_args()
    return args

def run_binee(testbin, showdll, loadlibs):
    proc = ["./binee", testbin, "-vv"]
    if showdll:
        proc.append("-d")
    if loadlibs:
        proc.append('-l')
    process = Popen(proc, stdout=PIPE, stderr=PIPE)
    (output, err) = process.communicate()
    exit_code = process.wait()
    return output, err

class Window(object):
    def __init__(self, screen, title, height, width, items, x=0, y=0, box=True, selected=False, xpo=1, ypo=1, xpeo=1, ypeo=1):
        self.window = None
        self.height = height
        self.width = width
        self.box = box
        self.items = items
        self.title = title
        self.x = x
        self.y = y
        self.xpo = xpo
        self.ypo = ypo
        self.xpeo = xpeo
        self.ypeo = ypeo
        self.create_window(screen)
        self.selected = selected
        self.border = (0,0,0,0,0,0,0,0)
        self.title_offset = 1

    def set_border(self, border):
        self.border = border

    def create_window(self, screen):
        self.window = screen.subwin(self.height, self.width, self.y, self.x)

    def borderer(self):
        if self.box:
            if self.selected:
                self.window.attron(curses.color_pair(3))
            self.window.border(*self.border)
            if self.selected:
                self.window.attroff(curses.color_pair(3))
        if self.selected:
            self.window.addstr(0,self.title_offset, self.title, curses.color_pair(4))
        else:
            self.window.addstr(0,self.title_offset, self.title, curses.color_pair(2))

    def display(self):
        self.window.clear()
        self.borderer()
        temp = self.items
        for i, s in enumerate(temp.split(b'\n')):
            self.window.addstr(i+self.ypo, self.xpo, s)
        self.window.refresh()

    def update(self):
        self.display()

class Multi(Window):
    def create_window(self, screen):
        self.windows = []
        self.current = 0
        self.index = 0
        self.max_length = self.height - self.ypeo - self.ypo
        super().create_window(screen)
    
    def addwin(self, info):
        self.windows.append(info)

    def rotate_tab(self, direction=1):
        if self.current == len(self.windows) - 1:
            self.current = 0
        else:
            self.current += direction

    def update_sf(self):
        if self.index > 0:
            temp = []
            temp.append(self.items[0])
            for i, x in enumerate(self.items[:self.index]):
                if b'call' in x:
                    temp.append(self.items[i+1][:self.width-self.xpeo])
                if b'ret' in x:
                    temp.pop()
            if len(temp) > self.max_length:
                t = len(temp) - self.max_length
                temp = temp[t:]
                temp[0] = b'...'
            self.windows[self.current]['data'] = b'\n'.join(temp)

    def borderer(self):
        if self.box:
            if self.selected:
                self.window.attron(curses.color_pair(3))
            self.window.border(*self.border)
            if self.selected:
                self.window.attroff(curses.color_pair(3))
        place = 0
        for i, s in enumerate(self.windows):
            if self.selected:
                if i == self.current:
                    self.window.addstr(0,self.title_offset+place, s['title'], curses.color_pair(4))
                else:
                    self.window.addstr(0,self.title_offset+place, s['title'], curses.color_pair(3))
            else:
                if i == self.current:
                    self.window.addstr(0,self.title_offset+place, s['title'], curses.color_pair(2))
                else:
                    self.window.addstr(0,self.title_offset+place, s['title'], curses.color_pair(5))
            place += len(s['title']) + 1

    def display(self):
        self.window.clear()
        self.borderer()
        temp = self.windows[self.current]['data']
        for i, s in enumerate(temp.split(b'\n')):
            self.window.addstr(i+self.ypo, self.xpo, s)
        self.window.refresh()

    def update(self, index):
        self.index = index
        if self.current == 0:
            self.update_sf()
        self.display()


class Registers(Window):
    def display(self):
        self.window.clear()
        self.borderer()
        temp = self.items[0]
        for i, s in enumerate(temp.split(b'\n')):
            self.window.addstr(i+self.ypo, self.xpo, s)
        self.window.refresh()

    def update(self, index):
        if index == 0:
            old = 0
        else:
            old = index - 1
        self.window.clear()
        self.borderer()
        new_break = self.items[index].split(b'\n')
        if (index + 1) == old or (index - 1) == old:
            old_break = self.items[old].split(b'\n')
        else:
            old_break = new_break
        for i, s in enumerate(new_break):
            if s != old_break[i] and not s.startswith(b'eip'):
                self.window.addstr(i+self.ypo, self.xpo, s, curses.color_pair(1))
                update = old_break[i].split(b'  ')
                self.window.addstr(i+self.ypo, len(s)+self.xpo+1, update[-1], curses.color_pair(2))
            else:
                self.window.addstr(i+self.ypo, self.xpo, s)
        self.window.refresh()


class Instructions(Window):
    def update(self, index):
        self.window.clear()
        self.borderer()
        before = int((self.height-2)/2)
        after = (self.height-2) - before - 1
        temp = []
        for i in range(before, 0 , -1):
            if index-i < 0:
                temp.append("-")
            else:
                temp.append(self.items[index-i])
        place = len(temp)
        temp.append(self.items[index])
        for i in range(after):
            try:
                temp.append(self.items[index+i+1])
            except:
                temp.append("-")
        for i, s in enumerate(temp):
            if i == place:
                self.window.addstr(i+self.ypo, self.xpo+2, s[:self.width-2-self.xpeo], curses.color_pair(3))
                self.window.addstr(i+self.ypo, self.xpo, ">")
            else:
                self.window.addstr(i+self.ypo, self.xpo+2, s[:self.width-2-self.xpeo])
        self.window.refresh()


class Screen(object):
    def __init__(self, items=None, err=None):
        self.window = None
        self.height = 0
        self.width = 0
        self.windex = 0
        self.items = items
        self.err = err
        self.init_curses()
        self.max_lines = curses.LINES
        self.windows = {}
        self.selected = None
        self.window_order = []
        self.current = 0
        self.search = None

    def update_items(self, items):
        self.items = items

    def update_err(self, err):
        self.err = err

    def update_ignored(self, ignored):
        self.ignored = ignored

    def init_curses(self):
        self.window = curses.initscr()
        self.window.keypad(True)
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)

        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK) #linechange
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE) #oldline
        curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK) #instruction
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_GREEN) #selected
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK) # normal

        self.current = curses.color_pair(5)
        self.height, self.width = self.window.getmaxyx()
        self.window.clear()
        self.window.addstr(0,0,"Running...", curses.color_pair(2))
        self.window.refresh()

    def init_subwins(self):
        split = int(self.width/3)
        if split < 62:
            split = 62
        debug_height = int(self.height/3)+1
        instructions_height = self.height - debug_height
        in_height = debug_height - 1
        corner = curses.ACS_RTEE
        subwidth = self.width-(split+1)
        #instructions setup
        inst_temp = []
        for i in self.items:
            inst_temp.append(i.split(b'\n')[-2])
        #registers setup
        temp = []
        for i in self.items:
            x = i.split(b'\n')
            temp.append(b'\n'.join(x[:-2]))
        self.windows['registers'] = Registers(self.window, "Registers", self.height-1, split, temp)
        self.windows['registers'].set_border((0,0,0,0,0,curses.ACS_TTEE,0,curses.ACS_BTEE))
        self.window_order.append(self.windows['registers'])
        #setup multi window for debug and errors
        self.windows['multi'] = Multi(self.window, "Multi", debug_height, subwidth, inst_temp, x=split, xpo=0, ypeo=0)
        self.windows['multi'].set_border((" ",0,0," ",curses.ACS_HLINE,0," ",curses.ACS_VLINE))
        self.window_order.append(self.windows['multi'])
        #debug information
        self.windows['multi'].addwin({
            'title': 'Stack Frames',
            'data': inst_temp[0].split(b'\n')[0]
        })
        if self.ignored:
            self.windows['multi'].addwin({
                'title': 'Debug',
                'data': self.ignored
            })
        if self.err:
            self.windows['multi'].addwin({
                'title': 'Errors',
                'data': self.err
            })
        #display preliminary info
        for i in self.windows.values():
            i.display()
        #instructions setup
        self.selected = Instructions(self.window, "Instructions", instructions_height, subwidth, inst_temp, y=in_height, x=split, selected=True, xpo=0)

        self.selected.set_border((" ",0,0,0,curses.ACS_HLINE,corner,curses.ACS_HLINE,0))
        self.windows['instructions'] = self.selected
        self.window_order.append(self.windows['instructions'])
        self.windows['instructions'].update(0)
        self.current = len(self.window_order)-1
    
    def run(self):
        self.window.clear()
        self.init_subwins()
        try:
            self.input_stream()
        except KeyboardInterrupt:
            pass
        finally:
            curses.endwin()

    def validate(self, key):
        if key == 10:
            return 7
        else:
            return key

    def handle_input(self, c):
        inp = curses.newwin(1, 25, self.height-1, 0)
        inp.addstr(0,0, c)
        sub = inp.derwin(0, 1)
        tb = curses.textpad.Textbox(sub, insert_mode=True)
        inp.refresh()
        text = tb.edit(self.validate)
        if c == ":":
            return text
        if c == "/":
            self.search = []
            if text[:-1]:
                inst_temp = []
                for i in self.items:
                    inst_temp.append(i.split(b'\n')[-2])
                for i,x in enumerate(inst_temp):
                    if text[:-1] in str(x):
                        self.search.append(i)
                self.window.addstr(self.height-1,len(text)+1,"({})".format(len(self.search)))
                return 1
        return 0

    def input_stream(self):
        index, old = 0, 0
        while True:
            c = self.window.getch()
            if c == curses.KEY_UP or c == ord('k'):
                if index == 0:
                    continue
                if self.window_order[self.current] == self.windows["instructions"]:
                    old = index
                    index -= 1
            elif c == curses.KEY_DOWN or c == ord('j'):
                if index == len(output)-1:
                    continue
                if self.window_order[self.current] == self.windows["instructions"]:
                    old = index
                    index += 1
            elif c == curses.KEY_LEFT or c == ord('h'):
                if index == 0:
                    continue
                if self.window_order[self.current] == self.windows["registers"]:
                    old = index
                    index -= 1
            elif c == curses.KEY_RIGHT or c == ord('l'):
                if index == len(output)-1:
                    continue
                if self.window_order[self.current] == self.windows["registers"]:
                    old = index
                    index += 1
            elif c == curses.KEY_HOME or c == ord('g'):
                    old = index
                    index = 0
            elif c == curses.KEY_END or c == ord('G'):
                old = index
                index = len(output) - 1
            elif c == ord('r'):
                self.window_order[self.current].selected = False
                if self.current == len(self.window_order)-1:
                    self.current = 0
                else:
                    self.current += 1
                self.window_order[self.current].selected = True
            elif c == ord('R'):
                self.window_order[self.current].selected = False
                if self.current == 0:
                    self.current = len(self.window_order)-1
                else:
                    self.current -= 1
                self.window_order[self.current].selected = True
            elif c == ord('c'):
                self.windows['multi'].rotate_tab()
            elif c == ord('C'):
                self.windows['multi'].rotate_tab(-1)
            elif c == ord(':'):
                text = self.handle_input(chr(c))
                try:
                    old = index
                    index = int(text)
                except:
                    pass
            elif c == ord('/'):
                text = self.handle_input(chr(c))
                if text:
                    for x in self.search:
                        if x > index:
                            old = index
                            index = x
                            break
            elif c == ord('n'):
                if self.search:
                    for x in self.search:
                        if x > index:
                            old = index
                            index = x
                            break
            elif c == ord('N'):
                if self.search:
                    for x in reversed(self.search):
                        if x < index:
                            old = index
                            index = x
                            break
            elif c == ord('q'):
                break
            else:
                continue
            self.window.addstr(self.height-1,self.width-6,"{:>4}".format(index))
            for i in self.windows.values():
                i.update(index)


if __name__ == "__main__":
    args = parse_args()
    screen = Screen()
    output, err = run_binee(args.testbin, args.showdll, args.loadlibs)
    output = output.split(b"---\n")
    if output[0][:3] != b'eax':
        ignored = output[0]
        output = output[1:]
    screen.update_items(output)
    screen.update_err(err)
    screen.update_ignored(ignored)
    screen.run()
