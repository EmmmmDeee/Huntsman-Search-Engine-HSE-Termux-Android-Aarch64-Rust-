- The web console's Graph keeps the page answering on a big scan. It used to run the force layout
  over every pair of elements in each frame and keep one SVG circle per element, so a scan of 3,000
  elements drew about 3 frames a second on a phone-speed CPU, and leaving the Graph kept the layout
  running: the Log then took 5.6 seconds to appear. The layout now works at most 12 ms a frame,
  repels only near neighbours past 600 elements, stops after 20 seconds of work, and stops when the
  page leaves the Graph, which also lets the graph's elements go. Each data type's elements are
  dots in one path, so moving every element restyles a few paths rather than thousands of
  circles. The same 3,000-element scan now draws about 48 frames a second while it arranges, and
  the Log appears in under half a second. Tapping an element finds the one under the finger, and
  Save image keeps how each element is drawn. The browser check locks this at 4x CPU throttling.
