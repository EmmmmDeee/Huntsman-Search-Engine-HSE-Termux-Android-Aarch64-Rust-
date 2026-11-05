- The offline analysis (`GET /api/analyze`) now gives each pair of supplied coordinates its
  initial great-circle bearing, in degrees clockwise from true north, beside the distance. It is
  left out where no single direction exists: coincident or antipodal points, or a start exactly
  at a pole.
