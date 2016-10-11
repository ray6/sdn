'''
SDN project testing topo

       s1
      /  \
     s2  s3
     |    |
   host.. host...

Let h1 and h2 under vlan 1(s2)
Let h3 and h3 under vlan 2(s3)
=> vlan1: h1, h2
=> vlan2: h3, h4

In this switchtopo, the host will be set to wrong vlan
Simply set h1 under s3.
'''
from mininet.topo import Topo

class SwitchTopo( Topo ):
	
	def __init__( self , n=2 ):

		# Initialize topology
		Topo.__init__( self)

		# Add Host
		h1 = self.addHost( 'h1' )
		h2 = self.addHost( 'h2' )
		h3 = self.addHost( 'h3' )
		h4 = self.addHost( 'h4' )
		
		# Add Switch
		s1 = self.addSwitch( 's1' )
		s2 = self.addSwitch( 's2' )
		s3 = self.addSwitch( 's3' )

		# Add Link
		self.addLink( s1, s2 )
		self.addLink( s1, s3 )
		self.addLink( s3, h1 )
		self.addLink( s2, h2 )
		self.addLink( s3, h3 )
		self.addLink( s3, h4 )

topos = { 'SwitchTopo': ( lambda: SwitchTopo() ) }
         
