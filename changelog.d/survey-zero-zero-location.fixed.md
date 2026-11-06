- Network Survey LTE and NR imports no longer place a device at 0°, 0°. A row reporting latitude 0
  and longitude 0, which the app writes when the device had no fix, now keeps no location, as Wi-Fi
  and Bluetooth rows already did. All four importers now read a row's location through one rule,
  `rf::survey_csv::reported_fix`. That rule keeps the point, and its accuracy of at most 100 km,
  only when both are real, and otherwise keeps none of the three fields.
