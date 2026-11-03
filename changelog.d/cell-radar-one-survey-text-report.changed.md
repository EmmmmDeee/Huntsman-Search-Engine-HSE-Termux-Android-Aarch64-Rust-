- `radar survey-lte` and `radar survey-nr` write their text report through one renderer,
  `cell_radar::network_survey::render_survey`, which leads each cell line with the cell's own
  technology; the two per-technology copies of the same layout are gone. The output is unchanged
  and each command's report now has a regression test pinning its header and cell line.
