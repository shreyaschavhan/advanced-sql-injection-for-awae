-- List all directors of Pixar movies (alphabetically), without duplicates ✓
-- List the last four Pixar movies released (ordered from most recent to least) ✓
-- List the first five Pixar movies sorted alphabetically ✓
-- List the next five Pixar movies sorted alphabetically ✓

SELECT distinct director FROM movies order by director;
select * from movies order by year desc limit 4;
select * from movies order by title limit 5;
select * from movies order by title limit 5 offset 5;
