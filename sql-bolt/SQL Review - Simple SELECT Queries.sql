-- List all the Canadian cities and their populations ✓
-- Order all the cities in the United States by their latitude from north to south ✓
-- List all the cities west of Chicago, ordered from west to east ✓
-- List the two largest cities in Mexico (by population) ✓
-- List the third and fourth largest cities (by population) in the United States and their population ✓

select city, population from north_american_cities where country = 'Canada';
select * from north_american_cities where country = "United States" order by latitude desc;
select * from north_american_cities where longitude < (select longitude from north_american_cities where city = "Chicago") order by longitude;
select * from north_american_cities where country = "Mexico" order by population desc limit 2;
select city, population from north_american_cities where country = "United States" order by population desc limit 2 offset 2;
