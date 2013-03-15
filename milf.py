#
# milf.py
#
# Some useful methods in vulnerability discovery.
# Let the snake make your life a bit easier
#
# Implemented using the idaapi and idautils modules

import re

from idaapi import *
from idautils import *
from idc import *

########################################
# NetworkX (optional) support
# for advanced graphs
try:
    import networkx as nx
    import malplotlib.pyplot as plt
    NetworkX = True
except:
    print "[debug] Deactivating support for NetworkX library"
    NetworkX = False

###################################################################################################
class IDAnalyzer():
    
    
    def __init__(self, debug = False, nx_support = True):
        ''' initialization of the main class '''
        self.import_dict = dict()
        self.debug = debug
        self.nx_support = nx_support

                    
        # Create a dictionary with all imports.
        # It populates self.import_dict
        self._enum_all_imports()
        
    
    def banner(self):
        ''' It has to be :) '''
        
        print "IDAnalyzer.\n"
        print "it's python, biatch\n"
                
                
    def mark_dangerous(self):    
        '''
        Colorize dangerous function calls!
        No arguments.
        
        @return: True '''
        
        dangerousFuncs = ["strcpy", "strncpy", "memmove", "memcpy", "sprintf", "lstrcpyW", "lstrcpyA", "memset"]
                
        # Loop from start to end within the current segment
        for FuncName in dangerousFuncs:
            func_addr = LocByName(FuncName)
            if self.debug:
                print "Function %s at %08x" % (FuncName, func_addr)
            
            # find all code references to the function
            for ref in CodeRefsTo(func_addr, True):
                if self.debug:
                    print "\tcalled from %s (%08x)" % (GetFunctionName(ref), ref)
                # Color the function call *RED*
                SetColor(ref, CIC_ITEM, 0x2020c0)
        
        return True
        
                
    def mark_switches(self, graph, color = 0x20c020):
        '''
        Convenience function. It colors all switches in a graph.
        @type graph: dictionary
        @param graph: Complex data structure. See connect_graph()
        
        @type color: hex
        @param color:(optional) color to mark the switches
         
        @return: True '''
        
        switches = self.enum_switches(graph)
        for sw in switches.keys():
            SetColor(sw, CIC_ITEM, color)
        
        
        return True
        
        
    def _enum_all_imports(self):
        '''
        Useful afterwards for resolving addresses to imports.
        Following code has been taken shamelessly from the "ex_imports.py" distribution example :)
        
        @rtype: dictionary
        @return: dictionary containing import name & address { name : idata_ea } '''
        
        nimps = get_import_module_qty() # How many modules imported?
        
        if self.debug:
            print "[debug] Found %d imported modules" % nimps
        
        for i in xrange(0, nimps):
            name = get_import_module_name(i)
            if not name:
                print "[x] Could not get import module name for #%d" % i
                continue
            
            # The import_dict dictionary will be filled
            # through this callback function (_imp_cb)
            enum_import_names(i, self._imp_cb)
             
        return self.import_dict  
    
    
    def _imp_cb(self, ea, name, ord):
        '''
        Used by _enum_all_imports.
        Callback function used by idaapi.enum_import_names()
        
        @return: True ''' 
        if not name:
            self.import_dict[ord] = ea
        else:
            self.import_dict[name] = ea
            
        return True
 
    
    def _find_import_name(self, iaddr):
        '''
        Translates addresses to import names through a dictionary lookup.
        
        @type iaddr: address
        @param iaddr: Address of import
        
        @return: name (if successful) or same argument (on failure)  '''
        
        for k in self.import_dict.keys():
            if self.import_dict[k] == iaddr:
                name = k
                
        if name:
            return name
        else:
            return iaddr
    
    
    def graph_down(self, ea, graph = {}, path = set([])):
        '''
        Creates a downgraph of xrefs FROM this function.
        Calling it recursively allow us to get infinite depth.
        
        @type ea: ()
        @param ea: address of ROOT NODE
        
        @rtype: dictionary
        @return: Dictionary of function ea's and child *addresses* { ea : [c1_ea, c2_ea, ...] } '''
        
        graph[ea] = list()    # Create a new entry on the graph dictionary {node: [child1, child2, ...], ...}
        path.add(ea)        # This is a set, therefore the add() method
        
        # Iterate through all function instructions and take only call instructions
        for x in [x for x in FuncItems(ea) if is_call_insn(x)]:        # Take the call elements
            for xref in XrefsFrom(x, XREF_FAR):                                   
                if not xref.iscode:
                    continue
                        
                if xref.to not in path:        # Eliminates recursions
                    graph[ea].append(xref.to)
                    self.graph_down(xref.to, graph, path)
                    
        return graph


    def graph_up(self, ea, graph = {}, path = set([])):
        '''
        Creates an upgraph of xrefs TO this function.
        Calling it recursively allow us to get infinite depth.
        
        @type ea: address
        @param ea: address of ROOT NODE (bottom)
        
        @rtype: dictionary
        @return: Dictionary of function ea's and parent addresses { ea : [p1_ea, p2_ea, ...] } '''
        
        graph[ea] = list()    # Create a new entry on the graph dictionary {node: [child1, child2, ...], ...}
        path.add(ea)        # This is a set, therefore the add() method
        
    
        for xref in XrefsTo(ea, XREF_FAR):
            if not xref.iscode:
                continue
            
            func = get_func(xref.frm) # self.func -> idaapi.func_t
            if not func:
                continue
            else:
                caller_addr = func.startEA
                                
            if caller_addr not in path:        # Eliminates recursions
                graph[ea].append(caller_addr)
                self.graph_up(caller_addr, graph, path)
                
                
        return graph


    def _colorize_graph(self, node_list, color = 0x2020c0):
        '''
        Internal method. See show_path() for an example wrapper.
        It paints a *list* of functions with some color.
        
        @type graph: List
        @param graph: List of nodes_ea
        
        @type color: hex
        @param color: (optional) color to paint the functions  '''

        for x in node_list:
            SetColor(x, CIC_FUNC, color)
        
        return True
    
        
    def reset_colorize_graph(self, c_graph):
        '''
        Convenience method.
        Set color back to white for selected graph.
        
        @type graph: List
        @param graph: List of nodes
        
        @note: Call with "all" string to reset the whole module. '''

        WHITE = 0xffffff
        
        if c_graph == 'all':
            for function in Functions():
                SetColor(function, CIC_FUNC, WHITE)
        else:
            self._colorize_graph(c_graph, WHITE)
            
        return True
    
        
    def _translate_ea_name(self, ea):
        '''
        Translates an ea to a function/import name.
        
        @type ea: address
        @param ea: address to lookup
        
        @return: function/import name (on success) or same argument (on failure) '''
        
        t = GetFunctionName(ea)
        if not t:
            if SegName(ea) == '.idata':
                # The address is inside the imports section
                t = self._find_import_name(ea)
                if not t:
                    t = ea
            else:
                t = ea
                
        return t
    
        
    def translate_graph(self, graph):
        '''
        Takes a graph, { node: [child1, child2, ...], ...}
        and lookup as many function names as possible.
        
        @type graph: dictionary
        @param graph: dictionary of function ea's and "child" nodes { ea : [c1_ea, c2_ea, ...] }
        
        @rtype: dictionary
        @return: same dictionary but names instead of ea's (where possible) '''
        
        translated_graph = dict()
        
        # This loop translates the dict keys (nodes)
        for node in graph.keys():
            translated_key = self._translate_ea_name(node)
            translated_graph[translated_key] = list()
            # This loop translates the dict values (children)
            for child in graph[node]: # traverses a list
                translated_graph[translated_key].append(self._translate_ea_name(child))
                    
            
        return translated_graph         



    def connect_graph(self, origin, destination):
        '''
        Take a wild guess...
        
        @type origin: string
        @param origin: Function NAME
        
        @type destination: string
        @param destination: Function NAME
        
        @rtype: dictionary
        @return: Complex data  { 
                                 node_ea : {
                                            'node': node_ea, 
                                            'children': [child1_ea, child2_ea...],
                                            'parents': [parent1_ea, parent2_ea] 
                                            },
                                 ...} '''

        gdown = self.graph_down(LocByName(origin))
        gup = self.graph_up(LocByName(destination))
        
        gconnect = dict()
        
        for node_ea in gdown.keys():
            if node_ea in gup.keys():
                gconnect[node_ea] = dict()
                gconnect[node_ea]['node'] = node_ea
                gconnect[node_ea]['children'] = gdown[node_ea]
                gconnect[node_ea]['parents'] = gup[node_ea]
            else:
                pass
        
        
        return gconnect
    
    
    def connect_graph_import(self, origin, destination):
        '''
        Wrapper to connect_graph(). This allows origin to be an import.
        Ex. Graph between "recv" and "WriteFile"
        
        @type origin: string
        @param origin: Function NAME
        
        @type destination: string
        @param destination: Function NAME
        
        @note: This returns several "connect graphs", one for every function 
               calling the "origin" import. Indexed by address.
               See connect_graph() for graph type definition.
               
        @rtype:  dictionary
        @return: Complex data {imp_caller1_ea : connect_graph1, ...} '''
        
        graph_dict = dict()
        import_callers_dict = self._find_import_callers(origin)
        
        for imp_caller_addr in import_callers_dict.keys():
            # imp_caller_addr is the address within the function, where 
            # the actual call instruction is located, not the ea (beginning) 
            imp_caller_name = GetFunctionName(imp_caller_addr)
            imp_caller_ea = LocByName(imp_caller_name)
            graph_dict[imp_caller_ea] = self.connect_graph(imp_caller_name, destination)
            
        return graph_dict
    
         
        
    def advanced_connect_graph(self, origin, destination):
        '''
        Using networkx library.
        http://networkx.lanl.gov
        @todo: As with ConnectGraph!OnRefresh, improve the clumsy algorithm :) '''
        
        if self.nx_support:
            
            gdown = self.graph_down(LocByName(origin))
            gup = self.graph_up(LocByName(destination))
            
            nx_gconnect = nx.DiGraph()
            
            gconnect = self.connect_graph(origin, destination)
            
            for x in self.gconnect.itervalues():
                node_ea = x['node']
                nx_gconnect.add_node(node_ea)
                for c in x['children']:
                    try:
                        nx_gconnect.add_node(c)
                        nx_gconnect.add_edge(node_ea, c)
                    except:
                        continue
                for p in x['parents']:
                    try:
                        nx_gconnect.add_node(p)
                        nx_gconnect.add_edge(p, node_ea)
                    except:
                        continue
                    
            nx.draw(nx_gconnect)
            plt.show()
            
            return True
                            
        else:
            print "[debug] Sorry, support for networkx is *disabled*"
            return False
        
        
        
    def show_path(self, origin, destination, color = 0x2020c0):
        '''
        Colorizes a path.
        Originally though to be useful to visualize "connect graphs".
        
        @type origin: string
        @param origin: Function NAME
        
        @type destination: string
        @param destination: Function NAME
        
        @rtype: dictionary
        @return: Complex struct. See connect_graph() '''
        
        conn_graph = self.connect_graph(origin, destination)
        
        # The connection graph is a complex data structure, but
        # _colorize_graph() argument is a list of nodes
        graph_list = [x['node'] for x in conn_graph.itervalues()]
        
        self._colorize_graph(graph_list, color)
        
        return conn_graph
    
    
    def enum_switches(self, graph):
        '''
        Enumerate all switches in downgraph
        Shamelessly copied from Aaron Portnoy :)
        
        @type graph: graph
        @param graph: Complex structure. See connect_graph()
        
        @rtype: dictionary
        @return: dictionary { address : [cmp_mnem, disasm] } '''

        switch_dict = dict()
        jmpList = ['jmp', 'jz', 'jnz', 'jg', 'jl', 'ja', 'jb']
                
        # Extract a *list* of nodes from the graph data structure
        graph_list = [x['node'] for x in graph.itervalues()]
                 
        for func_start in graph_list:
            # if the function end isn't defined (probably a library call) then skip it
            func_end = FindFuncEnd(func_start)
            if func_end == 0xFFFFFFFF:
                continue

            for instr in FuncItems(func_start):
                # check for switch jump                    
                if GetMnem(instr) in jmpList:
                    # step backwards and find the cmp for the # of cases (if possible)
                    prev_instruction = PrevHead(instr, 0)

                    count = 5
                    while count > 0:
                        if GetMnem(prev_instruction) == 'cmp':
                            # get comparison number, plus for for case 0
                            cmp_mnem = GetDisasm(prev_instruction)
                            switch_dict[instr] = [cmp_mnem, GetDisasm(instr)]
                            break
                        
                    prev_instruction = PrevHead(prev_instruction, 0)    
                    count -= 1


        return switch_dict
    
    
    def imm_compares(self, graph):
        '''
        Find all immediate compares in a graph.
        It's useful when analyzing proprietary formats.

        @type graph: graph
        @param graph: Complex data structure. See connect_graph()
        
        @rtype: dictionary
        @return: dictionary of { addr : [op1, op2], ... } '''
        
        imm_cmp = dict()
        
        # Extract a *list* of nodes from the graph data structure
        graph_list = [x['node'] for x in graph.itervalues()]
        
        for func_start in graph_list:
            # if the function end isn't defined (probably a library call) then skip it
            func_end = FindFuncEnd(func_start)
            if func_end == 0xFFFFFFFF:
                continue

            for instr in FuncItems(func_start):
                disasm = GetDisasm(instr)
                if 'cmp' in disasm:
                    if GetOpType(instr, 1) == 5: # immediate value
                        if self.debug:
                            print "[debug] imm cmp at 0x%08x: %s" % (instr, GetDisasm(instr))
                        imm_cmp[instr] = [GetOpnd(instr, 0), GetOpnd(instr, 1)]
                        

        return imm_cmp


    def mark_imm_compares(self, color = 0x2020c0):
        '''
        Mark all immediate compares in the current function.
        Very useful when debugging parsers, for example.
        
        @type color: hex
        @param color: color for the mark '''
        
        for instr in FuncItems(ScreenEA()):
            disasm = GetDisasm(instr)
            if "cmp" in disasm:
                if GetOpType(instr, 1) == 5: # immediate value
                    if self.debug:
                        print "[debug] imm cmp at 0x%08x: %s" % (instr, GetDisasm(instr))
                    SetColor(instr, CIC_ITEM, color)
                    
        return True
    
    
    def function_bb_connect(self, bb_src_ea, bb_dst_ea, color = 0x2020c0):
        '''
        Graphically connect (color) basic blocks within a function.
        It could save your life! :) '''
        
        set_down = set([])
        set_up = set([])
        self.color = color
        
        
        # Nasty trick to get function's start EA
        f = get_func(bb_src_ea) # func_t object
        
        
        # Calculate the downgraph (originating at bb_src_ea)
        set_down = self._aux_calc_down_set(f, [bb_src_ea])
            
        # Calculate the upgraph set (originating at bb_dst_ea)
        set_up = self._aux_calc_up_set(f, [bb_dst_ea])
        
        ConnectedPaths = set_down.intersection(set_up)
        
        if ConnectedPaths:
            for PathBlock in ConnectedPaths:
                SetColor(PathBlock, CIC_ITEM, self.color)
        else:
            print "[debug] No path connecting those two basic blocks :("


    def _aux_calc_down_set(self, f, CurrentBlockLayer, DownGraphBlockSet = set([])):
        '''
        Analogous to graph_down().
        To set the "root" block, call with CurrentBlockLayer = [bb_src_ea] 
        
        @rtype: set
        @return: set containing upgraph blocks '''
        
        self.FuncFlowChart = FlowChart(f)
        self.CurrentBlockLayer = CurrentBlockLayer
        self.NextBlockLayer = list()
        
        # Iterate through all basic blocks and get the egress connections.
        for bb in self.CurrentBlockLayer:                    # bb: address
            block = self._aux_lookup_ea_bb(f, bb)
            for enode in block.succs():                        # enode: basic block type
                if enode.startEA not in DownGraphBlockSet:    # Eliminates recursions
                    self.NextBlockLayer.append(enode.startEA)
                    DownGraphBlockSet.add(enode.startEA)
                    self._aux_calc_down_set(f, self.NextBlockLayer, DownGraphBlockSet)
                
        return DownGraphBlockSet
        
        
    def _aux_lookup_ea_bb(self, f, ea):
        '''
        Returns a basic block object given an address
        
        @type f: func_t object
        @param f: represents the function of interest
        
        @type ea: address
        @param ea: address of the basic block
        
        @rtype: Basic Block Object
        @return: well... a basic block object :) '''
        
        self.f = f
        self.ea = ea
        self.FlowChart = FlowChart(f)
        
        for bb in self.FlowChart:
            if bb.startEA == self.ea:
                return bb
            
        return False
        
        
        
        
    def _aux_calc_up_set(self, f, CurrentBlockLayer, UpGraphBlockSet = set([])):
        '''
        Auxiliary function. I couldn't make Basic Block preds() work,
        so I need to calculate the upgraph myself.
        Note: preds(), I kill you! :) '''
        
        self.FuncFlowChart = FlowChart(f)
        self.CurrentBlockLayer = CurrentBlockLayer
        self.NextBlockLayer = list()
        
        
        for block in self.FuncFlowChart: # full lookup (it could be enhanced)
            for bsuccs in block.succs():    # .succs() returns a generator
                if bsuccs.startEA in CurrentBlockLayer: # it's a parent
                    if block.startEA not in UpGraphBlockSet:
                        self.NextBlockLayer.append(block.startEA)
                        UpGraphBlockSet.add(block.startEA)
                        self._aux_calc_up_set(f, self.NextBlockLayer, UpGraphBlockSet)
        
        return UpGraphBlockSet
        
        
        
        
                    
    def function_graph(self, ea):
        '''
        It creates a graph of basic blocks and their children.
        
        @type ea: address
        @param ea: address anywhere within the analyzed function.
        
        @rtype: dictionary
        @return: dictionary { block_ea: [branch1_ea, branch2_ea], ... } '''
        
        bb_dict = dict()
        f = FlowChart(get_func(ea))    #FlowChart object
        
        for bb in f:
            bb_dict[bb.startEA] = list()        # Dict of BasicBlock objects
            for child in bb.succs():
                bb_dict[bb.startEA].append(child.startEA)
        
        return bb_dict
    

    
    def locate_function_call(self, func_name, callee):
        '''
        Convenience function. It locates a particular function call *within a function*.
        
        @type func_name: string
        @param func_name: NAME of the function containing the call
        
        @type callee: string
        @param callee: NAME of the function being called
        
        @rtype: List
        @return: List of addresses ("call callee" instructions) 
        
        @todo: IIRC this needs to be improved/fixed '''
        
        call_addr_list = list()
        func_ea = LocByName(func_name)    # returns startEA
        
        # If there's a thunk, it won't be called directly from the function (dough!)
        # Is the callee located inside .idata section and called through a thunk?
        callee_ea = LocByName(callee)
        xr = XrefsTo(callee_ea, True)
        xrl = list(xr) # ugly but easy
        if len(xrl) == 1:  # thunks are call bottlenecks
            xrf = get_func(xrl[0].frm)
            if (xrf.flags & idaapi.FUNC_THUNK) != 0:
                # it IS a thunk
                callee = GetFunctionName(xrl[0].frm)
                
        for instr in FuncItems(func_ea):
            disasm = GetDisasm(instr)
            if "call" in disasm and callee in disasm:
                call_addr_list.append(instr)
                if self.debug:
                    print "[debug] Found", disasm, "at %08x" % instr
        
        return call_addr_list
    
    
    def dangerous_size_param(self, color = 0xFF8000, mark = False):
        '''
        Some functions copy buffers of size specified by a size_t parameter.
        If this isn't a constant, there's a chance that it can be manipulated 
        leading to a buffer overflow.
        Example: void *memset( void *dest, int c, size_t count ); '''
        
        regexp = ".*memset|.*memcpy|.*memmove|.*strncpy|.*strcpy.*|.*sncpy"
        candidate_dict = self._find_import_callers(regexp)
        
        for candidate_ea, imp_ea_list in candidate_dict.iteritems():
            # For every candidate function, look for the calls 
            # to dangerous functions within it
            for danger_ea in imp_ea_list:
                func_caller = GetFunctionName(candidate_ea)
                imp_callee = Name(danger_ea)
                # List of addresses within the function ("call dangerous_func")
                addr_list = self.locate_function_call(func_caller, imp_callee)
            
                if addr_list:
                    print "------ Analysing %s ------" % func_caller
                    tmp_push_list = list()
                    func_start = LocByName(func_caller)
                    func_end = FindFuncEnd(func_start)
                    # if the function end isn't defined (probably a library call) then skip it
                    if func_end == 0xFFFFFFFF:
                        continue
                    
                    for instr in FuncItems(func_start):
                        disasm = GetDisasm(instr)
                        # List with addresses of push instructions
                        if "push" in disasm:
                            tmp_push_list.append(instr) # address of the push instruction
                        elif instr in addr_list:
                            if len(tmp_push_list) >= 3: # sanity check :)
                                push_size_addr = tmp_push_list[-3]
                                if GetOpType(push_size_addr, 0) < 5: # This can be improved
                                    print "[debug] %08x - %s" % (instr, GetDisasm(push_size_addr))
                                    if mark == True:
                                        SetColor(instr, CIC_ITEM, 0x2020c0)
                        else:
                            continue
                
        return True
        
        
    def locate_file_io(self, interactive = False):
        '''
        Convenience function
        Finds interesting IO related *imports* and the functions calling them.
        Call with interactive = True to display a custom viewer ;)
        
        @rtype: Dictionary (of lists)
        @return: Dictionary containing the functions calling the imported functions,
                 {fn_ea: [file_io1_ea, file_io2_ea, ...], ...} '''
        
        # The meat and potatoes is the regexp
        regexp = ".*readf.*|.*write.*|.*openf.*|f.*print.*"
        callerDict = self._find_import_callers(regexp)
        
        if interactive:
            file_io_cview = SuspiciousFuncsViewer()
            if file_io_cview.Create("File IO", callerDict):                    
                file_io_cview.Show()
            else:
                print "[debug] Failed to create custom view: File IO" 
            
            
        return callerDict
    
    
    def locate_net_io(self, interactive = False):
        '''
        Convenience function
        Finds interesting network related *imports* and the functions calling them.
        Call with interactive = True to display a custom viewer ;)
        
        @rtype: Dictionary (of lists)
        @return: Dictionary containing the functions calling the imported functions,
                 {fn_ea: [net_io1_ea, net_io2_ea, ...], ...} '''
        
        # The meat and potatoes is the regexp
        regexp = "recv|recvfrom|wsa.*"
        callerDict = self._find_import_callers(regexp)

        if interactive:
            net_io_cview = SuspiciousFuncsViewer()
            if net_io_cview.Create("Net IO", callerDict):
                net_io_cview.Show()
            else:
                print "[debug] Failed to create custom view: Net IO" 

        
        return callerDict
    
        
    def locate_allocs(self, interactive = False):
        '''
        Convenience function
        Finds interesting allocation related *imports* and the functions calling them.
        Call with interactive = True to display a custom viewer ;)
        
        @rtype: Dictionary (of lists)
        @return: Dictionary containing the functions calling the imported functions,
                 {fn_ea: [alloc1_ea, alloc2_ea, ...], ...} '''
        
        # The meat and potatoes is the regexp
        regexp = ".*alloc.*|.*free.*"
        callerDict = self._find_import_callers(regexp)

        if interactive:
            allocs_cview = SuspiciousFuncsViewer()
            if allocs_cview.Create("Allocs", callerDict):
                allocs_cview.Show()
            else:
                print "[debug] Failed to create custom view: Allocs" 

        
        return callerDict


    def locate_most_referenced(self, number = 10, interactive = False):
        ''' Identifying these is an important first step '''
        
        self.number = number
        self.interactive = interactive
        referenceDict = dict()
        topReferencesDict = dict()
        
        for funcAddr in Functions():
            refNumber = sum(1 for e in XrefsTo(funcAddr, True)) # stackoverflow ;)
            referenceDict[funcAddr] = refNumber
        
        # Log to IDA's output window and to a custom viewer <3
        print "Top %d most referenced functions" % self.number
        
        NrResults = 0
        # Let's order this stuff nicely
        for func_ea, refnumber in sorted(referenceDict.iteritems(), reverse = True, key = lambda (k, v): (v, k)):
            NrResults += 1 # control counter
            if NrResults > self.number:
                break
            else:
                print "%s : %s" % (GetFunctionName(func_ea), refnumber)
                topReferencesDict[func_ea] = refnumber
                
        # Create the custom viewer
        if self.interactive:
            toprefs_cview = SuspiciousFuncsViewer()
            if toprefs_cview.Create("Top referenced", topReferencesDict):
                toprefs_cview.Show()
            else:
                print "[debug] Failed to create custom view: Top referenced"
                
                
        return topReferencesDict

        
    def _find_import_callers(self, regexp):
        '''
        Finds interesting imported functions and the nodes that call them. 
        Very handy in locating user inputs.
        
        @attention: There are imports called through a thunk and directly.
        @rtype: Dictionary (of lists)
        @return: Dictionary containing *the address of the functions* 
                 calling the imports,
                 {fn_call_ea: [idata1_ea, idata2_ea, ...], ...}
                  
        @todo: IIRC this needs some review '''
        
        importCallers = dict()
        importPattern = re.compile(regexp, re.IGNORECASE)
        
        for imp_name, idata_ea in self.import_dict.iteritems():
            # This dict has the *IAT names* (i.e. __imp_ReadFile, within the .idata section)
            if importPattern.match(imp_name):
                for import_caller in XrefsTo(idata_ea, True):
                    import_caller_addr = import_caller.frm
                    import_caller_fn = get_func(import_caller_addr)
                    
                    if import_caller_fn:
                        
                        # Check if caller is a THUNK
                        if (import_caller_fn.flags & idaapi.FUNC_THUNK) != 0:
                            # It IS a thunk
                            for thunk_caller in XrefsTo(import_caller_addr, True):
                                thunk_caller_fn = get_func(thunk_caller.frm)
                                import_caller_ea = thunk_caller_fn.startEA
                                if importCallers.has_key(import_caller_ea):
                                    # Remove nasty duplicates
                                    if idata_ea in importCallers[import_caller_ea]:
                                        continue
                                    else:
                                        importCallers[import_caller_ea].append(idata_ea)
                                else:
                                    importCallers[import_caller_ea] = [idata_ea]
                                    
                        else:
                            # It is NOT a thunk, no need for recursion                    
                            import_caller_ea = import_caller_fn.startEA
                            
                            if importCallers.has_key(import_caller_ea):
                                # Remove nasty duplicates
                                if idata_ea in importCallers[import_caller_ea]:
                                    continue
                                else:
                                    importCallers[import_caller_ea].append(idata_ea)
                            else:
                                importCallers[import_caller_ea] = [idata_ea]

                    else:
                        #import_caller_fn is None
                        pass
                    
                    
        return importCallers


    def export_functions_to_file(self, extended = False):
        '''
        Export all the function start addresses to a file. This will be used by a tracer.
        The extended option logs the number of arguments as well. '''
        
        self.extended = extended
        filename = AskFile(1, "*.*", "File to export functions to?")
        
        f = open(filename, "w")
        print "Exporting function addresses to %s\n" % filename
        
        idx = 0
        
        # The string format is:
        # 0xAAAAAAAA-0xBBBBBBBB {ea_start, ea_end}
        
        for function_start in Functions():
            function_end = GetFunctionAttr(function_start, FUNCATTR_END)
            # Below I've just stripped the leading '0x' chars
            addr_interval_string = str(hex(function_start)).split('0x')[1] + '-' + str(hex(function_end)).split('0x')[1]
            
            if self.extended:
                # Get the number of function args
                frame = GetFrame(f)
                if frame is None: continue
                ret = GetMemberOffset(frame, " r")
                if ret == -1: continue
                firstArg = ret + 4
                NumberOfArguments = (GetStrucSize(frame) - firstArg)/4     # Every arg on the stack is 4 bytes long
                addr_interval_string += ",%d" % NumberOfArguments 

            f.write(addr_interval_string  + '\n')
            idx += 1
            
        f.close()
        
        print "%d functions written to disk" % idx
            

    def import_functions_from_file(self):
        '''
        Import all the function start addresses to a file.
        Rudimentary differential debugging, yay! '''    
        
        filename = AskFile(0, "*.*", "File to import functions from?")
        print "Importing function start addresses from %s\n" % filename
        
        idx = 0        
        f = open(filename, 'r')
        function_addresses = f.readlines()  # I still have to strip them
        f.close()
        
        imported_fn_dict = dict()
                
        for fa in function_addresses:
            f_addr = int(fa.split('-')[0], 16)
            imported_fn_dict[f_addr] = GetFunctionName(f_addr)
            SetColor(f_addr, CIC_FUNC, 0x188632)
            idx += 1
        
        print "[debug] %d functions imported from file" % idx
        
        # A custom viewer doesn't hurt :)
        imported_fn_cview = SuspiciousFuncsViewer()
        if imported_fn_cview.Create("Specific Functions", imported_fn_dict, onhint_active = False):                    
            imported_fn_cview.Show()
        else:
            print "[debug] Failed to create custom view: Specific Functions" 
    

    def import_basic_blocks_from_file(self):
        '''
        Import hit basic blocks from a detailed PIN Trace.
        A choser allows to somehow re-trace execution within 
        the functions we are interested in. '''    
        
        filename = AskFile(0, "*.*", "File to import basic blocks from?")
        print "Importing basic block addresses from %s\n" % filename
        
        token = '$'
        idx = 0
                
        f = open(filename, 'r')
        lines = f.readlines()
        f.close()

        bb_addresses = list()
        
        for li in lines:
            if token in li:
                bb_addresses.append(int(li.split(token)[1].strip(), 16))
                
        # Process the list for loops
        analyzed_trace = self._find_trace_loops(bb_addresses)
        
        # Love lambda functions :)
        TraceElements = [[GetFunctionName(x), hex(x), GetDisasm(x)] for x in bb_addresses]
        MilfBBTraceSelector("Basic blocks hit during Intel's PIN trace", TraceElements, 0, parent = self).show()
            
        
    def _find_trace_loops(self, bb_addr):
        '''
        Simple algorithm to reduce small loops in trace files.
        Loops of the type a -> b -> a ... are identified.
        @return: two-dimensional list (int addr, str comment), where the comment 
                 indicate the number of times the loop occurred or empty string if none. '''
        
        idx     = 0
        loop     = 0
        
        while idx < len(bb_addr):
            # Implement a simple logic here
            pass
        
        
        
        
        
    def usage(self):
        '''On screen help'''
        
        print "Exported ia object (IDAnalyzer class instance)"
        print "some cool methods:\n"
        
        methods = []
        for x in dir(self):
            if not x.startswith("_"):
                if callable(getattr(self, x)):
                    methods.append(str(x))
        
        for m in methods:
            print "- ia." + m
        
       
       
###################################################################################################
class ConnectGraph(GraphViewer):
    
    def __init__(self, graph):
        GraphViewer.__init__(self, "Connect Graph")
        self.graph = graph

        
    def OnRefresh(self):
        '''@todo: this algorithm is a bit clumsy. Get back to it.'''
        
        self.Clear()
        idNode = dict() # { node_ea : node_id }
        
        for x in self.graph.itervalues():
            # First, add all nodes and populate the idNode list
            node_ea = x['node']
            idNode[node_ea] = self.AddNode(node_ea)
        
        for node_ea, x in self.graph.iteritems():
            # Link the node with parents and children
            # These 'children' elements are *all* references from the node,
            # not just the ones belonging to the connected graph.
            for c in x['children']:
                try:
                    self.AddEdge(idNode[node_ea], idNode[c])
                except:
                    continue
                
            for p in x['parents']:
                try:
                    self.AddEdge(idNode[p], idNode[node_ea])
                except:
                    continue
        
        # Calculate a handy reverse dictionary { node_id: node_ea}
        self.AddrNode = dict()
        for ea,id in idNode.iteritems():
            self.AddrNode[id] = ea
                    
        return True


    def DisasmAround(self, node_id):
        '''
        Writes the function disassembly 
        (around interesting function calls)
        @todo: identify fn call with pure asm, not strings :/ '''
        
        interesting_fn_names = list()
        node_ea = self.AddrNode[node_id]
        
        # We are interested in the function calls from the node, which
        # are actually part of the connected graph :)
        for x in self.graph[node_ea]['children']:
            if x in self.graph.keys(): # node list
                interesting_fn_names.append(GetFunctionName(x))
        
        position = 0
        fi = FuncItems(node_ea)
        f_items = list(fi) # generator -> list
        
        NodeText = "[ %s ]\n\n" % GetFunctionName(node_ea)
        
        for ins in f_items:
            # Find call to interesting function and
            # slice around the call in disasm
            disasm = GetDisasm(ins)
            if "call" in disasm:
                for name in interesting_fn_names:
                    if name in disasm:
                        print "[debug] *** Found call", name, position
                        disasm_slice = f_items[position - 3 : position + 3]
                        for instr in disasm_slice:
                            #print "    [debug] disasm_around()", GetDisasm(instr)
                            NodeText += GetDisasm(instr)
                            NodeText += "\n"
                            
                        NodeText += "--------\n"                        
            
            position += 1
            
        return NodeText
    
    
    def OnGetText(self, node_id):
        return (self.DisasmAround(node_id), 0x800000)
    
    
    def OnDblClick(self, node_id):
        ''' Double clicking on a node, jump to it in disassembly '''
        Jump(self.AddrNode[node_id])
        return True
        
        
    def OnSelect(self, node_id):
        print "[debug]", hex(self.AddrNode[node_id]), "selected"
        return True
    
    
    def OnHint(self, node_id):
        return hex(self.AddrNode[node_id])
    
    
    def OnClick(self, node_id):
        return True
    
    
    def OnCommand(self, cmd_id):
        '''
        Triggered when a menu command is selected through the menu of hotkey
        @return: None '''
        
        if cmd_id == self.cmd_close:
            self.Close()
            return
        
            
    def Show(self):
        if not GraphViewer.Show(self):
            return False
        
        # Add some handy commands to the graph view :)
        self.cmd_close = self.AddCommand("Close", "F2")
        if self.cmd_close == 0:
            print "[debug] Failed to add popup menu item for GraphView"
        
        return True


###################################################################################################
class SuspiciousFuncsViewer(simplecustviewer_t):
    
    def Create(self, sn = None, dict_fn = None, onhint_active = True):
        '''
        This is analog to the __init__ method when superclassing.
        
        @todo: dict_refs connects line numbers (as the custom viewer) with function info.
               How will it work when we delete/add lines (de-synchronize?) '''
        
        self.dict_fn = dict_fn
        self.onhint_active = onhint_active
        
        
        title = "Hot spots"
        if sn:
            add_title = " (%s)" % sn
            title += add_title
        
        # Check that it doesn't exist already and Create it
        f = find_tform(title)
        if f:
            print "[debug] Form %s exists already" % title
            return False
        
        if not simplecustviewer_t.Create(self, title):
            return False
        
        
        # Write some information
        comment = idaapi.COLSTR("; Double click to follow", idaapi.SCOLOR_BINPREF)
        self.AddLine(comment)
        comment = idaapi.COLSTR("; Hover for preview", idaapi.SCOLOR_BINPREF)
        self.AddLine(comment)
        
        # Write entries
        if self.dict_fn:
            self.dict_refs = dict()
            
            line_idx = 2    # offset due to initial comments
            for fn_ea, imp_ea_list in self.dict_fn.iteritems():
                self.dict_refs[line_idx] = [fn_ea, imp_ea_list]
                
                EntryName = GetFunctionName(fn_ea)
                if not EntryName:
                    EntryName = hex(fn_ea)
                    
                self.AddEntry(EntryName)
                line_idx += 1
                

        
        # Some popup menu items go here...
        self.menu_jmp_graph = self.AddPopupMenu("Jump to graph", 'F2')
        self.menu_delete_line = self.AddPopupMenu("Delete current entry", 'F3')
        self.menu_mark_line = self.AddPopupMenu("Mark this entry", 'F4')
        
        return True


    def AddEntry(self, entry_text):
        '''
        I own you, machine
        '''    
        entry = idaapi.COLSTR(entry_text, idaapi.SCOLOR_STRING)
        self.AddLine(entry)
        
        return True

    
    def DelEntry(self, line_no):
        '''
        This is in case I would like to add, for example,
        a confirmation dialog in the future
        '''
        self.DelLine(line_no)
        
        return True

    
    def MarkCurrentLine(self):
        line_no = self.GetLineNo()
        line = self.GetCurrentLine(notags = 1)
        marked_line = idaapi.COLSTR("[x] " + line, idaapi.SCOLOR_NUMBER)
        self.EditLine(line_no, marked_line)
    
        return True

    
    def OnClick(self, shift):
        return True

    
    def OnDblClick(self, shift):
        fn_string = self.GetCurrentWord()
        if fn_string[:2] == '0x':
            fn_ea = int(fn_string, 16)
        else:
            fn_ea = LocByName(fn_string)
            
        Jump(fn_ea)
        
        return True

    
    def OnHint(self, lineno):
        
        if not self.onhint_active:
            pass
        
        if lineno < 2:
            return False
        
        OnHintParameter = self.dict_refs[lineno][1]
        if type(OnHintParameter) == list:
            hint_string = "It calls: "
            for c in OnHintParameter:
                hint_string += "%s, " % Name(c)
        else:
            hint_string = "%s" % OnHintParameter#
                
        color_hint = idaapi.COLSTR(hint_string, idaapi.SCOLOR_STRING)    
        return (1, color_hint)
    
    
    def OnKeyDown(self, vkey, shift):
        if vkey == 27:    # ESC
            self.Close()
        elif vkey == ord('R'):
            print "Refreshing..."
            self.Refresh()
        else:
            return False
        
        return True
    
    
    def OnPopup(self):
        pass
    
    
    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_jmp_graph:
            self.OnDblClick(None)
        elif menu_id == self.menu_delete_line:
            line_no = self.GetLineNo()
            self.DelEntry(line_no)
        elif menu_id == self.menu_mark_line:
            self.MarkCurrentLine()
        else:
            # Unhandled
            return False
        
        return True


###################################################################################################
class MilfPlugin(idaapi.plugin_t):
    ''' This registers the plugin within IDA Pro '''
    
    flags = 0
    comment = "MILF. Satisfying your (RE) basic needs."
    help = "For your everyday RE tasks"
    wanted_name = "MILF"
    wanted_hotkey = "Alt-F8"
    
    
    def init(self):
        idaapi.msg("MILF initialized\n")
        self.icon_id = 0
        # Instance of the IDAnalyzer class
        self.ia = IDAnalyzer(debug = True, nx_support = NetworkX)
        
        return idaapi.PLUGIN_KEEP
    
    
    def AddMenuElements(self):
        '''Menus are better than no GUI at all *sigh*'''
        
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Select Origin Basic Block", "", 0, self.MilfMarkOriginBB, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Select Destination Basic Block", "", 0, self.MilfMarkDestBB, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Connect Blocks!", "", 0, self.MilfConnectBlocks, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Most referenced functions", "", 0, self.MilfMostReferenced, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Connect Graph", "Ctrl+F8", 0, self.MilfConnGraph, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Mark dangerous functions", "Ctrl+F9", 0, self.MilfMarkDangerous, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Mark immediate compares", "Ctrl+F10", 0, self.MarkImmCompares, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Locate allocs", "Ctrl+F11", 0, self.MilfLocateAllocs, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Locate network IO", "Ctrl+F12", 0, self.MilfLocateNetIO, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Mark dangerous size params", "", 0, self.MilfMarkDangerousSize, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Reset all markings", "", 0, self.MilfResetMarkings, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Export function addresses to disk", "", 0, self.MilfExportFunctions, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Export function addresses (and arguments info) to disk", "", 0, self.MilfExportFunctionsAdvanced, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Import function addresses from file", "", 0, self.MilfImportFunctions, ())
        idaapi.add_menu_item("Edit/Plugins/", "MILF: Import basic blocks from file", "", 0, self.MilfImportBasicBlocks, ())

    
    def run(self, arg = 0):
        idaapi.msg("[debug] MILF's plugin_t run() called\n")
        idaapi.msg("You can start using MILF right now.\n")
        # Load icon from file (convenient but not portable :/)
        self.icon_id = idaapi.load_custom_icon(file_name = "M.ico")
        if self.icon_id == 0:
            raise RuntimeError("[debug] failed to load icon file")
        
        # Some menus are in order!
        self.AddMenuElements()
    
    
    def MilfMarkOriginBB(self):
        self.src_basic_block = ScreenEA()
        print "[Debug] Selected Origin Basic Block (0x%08x)" % self.src_basic_block
        
        return True
        
    
    def MilfMarkDestBB(self):
        self.dst_basic_block = ScreenEA()
        print "[Debug] Selected Destination Basic Block (0x%08x)" % self.dst_basic_block
        
        return True
    
    
    def MilfConnectBlocks(self):
        if self.src_basic_block and self.dst_basic_block:
            self.ia.function_bb_connect(self.src_basic_block, self.dst_basic_block)
            print "[Debug] Drawing connect graph..."
        else:
            print "[Debug] Check that you selected all parameters"
        
        return True

        
    def MilfMostReferenced(self, number = 10):
        self.ia.locate_most_referenced(number = 10, interactive = True)
        
        
    def MilfMarkDangerous(self):
        self.ia.mark_dangerous()
    
    
    def MarkImmCompares(self):
        self.ia.mark_imm_compares()
        
            
    def MilfConnGraph(self):        
        # Love lambda functions :)
        moduleFunctions = [[hex(x), GetFunctionName(x)] for x in Functions()]
        MilfFuncSelector("Select Functions to Connect", moduleFunctions, self.icon_id, parent = self).show()


    def MilfLocateAllocs(self):
        self.ia.locate_allocs(interactive = True)

        
    def MilfLocateNetIO(self):
        self.ia.locate_net_io(interactive = True)

        
    def MilfResetMarkings(self):
        self.ia.reset_colorize_graph('all')

        
    def MilfMarkDangerousSize(self):
        self.ia.dangerous_size_param(mark = True)

        
    def MilfExportFunctions(self):
        self.ia.export_functions_to_file()


    def MilfExportFunctionsAdvanced(self):
        self.ia.export_functions_to_file(extended = True)

        
    def MilfImportFunctions(self):
        self.ia.import_functions_from_file()

        
    def MilfImportBasicBlocks(self):
        self.ia.import_basic_blocks_from_file()
        
        
    def term(self):
        idaapi.msg("term() called\n")
        ######### Cleanup #########
        # Free the icon
        if self.icon_id != 0:
            idaapi.free_custom_icon(self.icon_id)


###################################################################################################
class MilfFuncSelector(Choose2):
    ''' Chooser class. Let's keep things pretty :P '''
    
    def __init__(self, title, items, icon, parent, embedded = False):
        Choose2.__init__(self, title, [["Address", 12], ["Functions", 30]], embedded = embedded)
        self.items = items
        self.icon = icon
        self.parent = parent
        self.g_origin = None
        self.g_destination = None
 
        
    def GetItems(self):
        return self.items
 
    
    def SetItems(self, items):
        self.items = [] if items is None else items
 
        
    def OnClose(self):
        pass
 
    
    def OnGetLine(self, n):
        return self.items[n]
 
    
    def OnGetSize(self):
        return len(self.items)
 
    
    def OnSelectLine(self, n):
        # Callback for double-clicks
        pass
 
    
    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_origin:
            # mark as source
            self.g_origin = self.items[n][1]
            print "[debug] Graph origin: %s" % self.g_origin
        elif cmd_id == self.cmd_dst:
            # mark as destination
            self.g_destination = self.items[n][1]
            print "[debug] Graph destination: %s" % self.g_destination
        elif cmd_id == self.cmd_graph:
            # Graph it!
            print "[debug] Creating Graph: %s -> %s" % (self.g_origin, self.g_destination)
            gc = self.parent.ia.connect_graph(self.g_origin, self.g_destination)
            if gc:
                gv = ConnectGraph(gc)
                gv.Show()               
        else:
            print "[debug] Command not understood"
        
        return True
    
    
    def show(self):
        # It replaces the native Show() method
        t = self.Show()
        if t < 0:
            return False
        else:
            # Add some context menus :)
            self.cmd_origin = self.AddCommand("Set as origin")
            self.cmd_dst = self.AddCommand("Set as destination")
            self.cmd_graph = self.AddCommand("Graph it")
            return True


###################################################################################################
class MilfBBTraceSelector(Choose2):
    ''' Displays the basic blocks hit during the Intel's PIN detailed trace. '''
    
    def __init__(self, title, items, icon, parent, embedded = False):
        Choose2.__init__(self, title, [["Function", 20], ["Address", 8], ["Disassembly", 20]], embedded = embedded)
        self.items = items
        self.icon = icon

        
    def GetItems(self):
        return self.items

    
    def SetItems(self, items):
        self.items = [] if items is None else items

        
    def OnClose(self):
        pass

    
    def OnGetLine(self, n):
        return self.items[n]

    
    def OnGetSize(self):
        return len(self.items)

    
    def OnSelectLine(self, n):
        ''' Callback for double-click '''
        
        trace_addr = int(self.items[n][1], 16)
        SetColor(trace_addr, CIC_ITEM, 0x3db43d)
        Jump(trace_addr)

    
    def OnCommand(self, n, cmd_id):
        '''Callback for contextual menu'''
        
        if cmd_id == self.cmd_follow:
            # jmp to position in graph view
            Jump(int(self.items[n][1], 16))
        else:
            print "[debug] Command not understood"
        
        return True
    
    
    def show(self):
        ''' It replaces the native Show() method '''
        
        t = self.Show()
        if t < 0:
            return False
        else:
            # Add some context menus :)
            self.cmd_follow = self.AddCommand("Follow in graph")
            return True
        
        
###################################################################################################
def PLUGIN_ENTRY():
    return MilfPlugin()
    
