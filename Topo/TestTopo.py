'''
SDN project testing topo
 host- s1-host
      /  \
     s2--s3
     |    |
   host.. host...

'''
from mininet.topo import Topo

class TestTopo( Topo ):

	def __init__( self , n=2 ):

		# Initialize topology
		Topo.__init__( self)

		# Add Host
		h1 = self.addHost( 'h1' )
		h2 = self.addHost( 'h2' )
		h3 = self.addHost( 'h3' )
		h4 = self.addHost( 'h4' )

                h5 = self.addHost( 'h5' )
		h6 = self.addHost( 'h6' )		

		# Add Switch
		s1 = self.addSwitch( 's1' )
		s2 = self.addSwitch( 's2' )
		s3 = self.addSwitch( 's3' )

		# Add Link
		self.addLink( s1, s2 )
		self.addLink( s1, s3 )
		self.addLink( s2, s3 )
		self.addLink( s2, h1 )
		self.addLink( s2, h2 )
                self.addLink( s1, h5 )
		self.addLink( s3, h3 )
		self.addLink( s3, h4 )

		self.addLink( s1, h6 )

topos = { 'TestTopo': ( lambda: TestTopo() ) }
