
require 'skyrack/gadget'

require 'rubygems'
require 'rgl/adjacency'
require 'rgl/dot'

class GadgetTree < RGL::DirectedAdjacencyGraph

    attr_accessor :ret

    def initialize(*args)
        @gadgets = {}
        super(*args)
    end

    def ret
        @ret_v ||= self.max
    end

    def ret_addr
        @ret_addr_v ||= ret.addr
    end

    def find_by_addr(addr)
        select { |e| e.addr == addr }.first
    end

    def include_addr?(addr)
        find_by_addr(addr)
    end

    def from_addr(addr)
        return @gadgets[addr] if @gadgets[addr]
        start = find_by_addr(addr)
        if start.nil? then
            puts "nothing found at 0x%06x" % addr
            return nil
        end
        gadget = Gadget[start]

        while gadget.last != ret do
            gadget << find_by_addr(gadget.last.next_instr_addr)
        end
        @gadgets[addr] = gadget
    end

    def ret_distance(instr)
        from_addr(instr.addr).size
    end

    def generate_expression_tree
        raise NotImplementedError
        #@expr_tree = ?
        browse_from_top do |instr|

        end
    end

    include RGL
    def to_dot_graph (params = {})
        $stdout.puts "here"
        params['name'] ||= self.class.name.gsub(/:/,'_')
        fontsize   = params['fontsize'] ? params['fontsize'] : '8'
        graph      = (directed? ? DOT::Digraph : DOT::Subgraph).new(params)
        edge_class = directed? ? DOT::DirectedEdge : DOT::Edge
        each_vertex do |v|
            name = v.to_s
            graph << DOT::Node.new('name'     => v.addr,
                                   'fontsize' => fontsize,
                                   'label'    => name)
        end
        each_edge do |u,v|
            graph << edge_class.new('from'     => u.addr,
                                    'to'       => v.addr,
                                    'fontsize' => fontsize)
        end
        graph
    end
end

