-- Find the domestic and international sales for each movie ✓
-- Show the sales numbers for each movie that did better internationally rather than domestically ✓
-- List all the movies by their ratings in descending order ✓

select * from movies inner join boxoffice on movies.id = boxoffice.movie_id;
select * from movies inner join boxoffice on movies.id = boxoffice.movie_id where boxoffice.domestic_sales < boxoffice.international_sales;
select * from movies inner join boxoffice on movies.id = boxoffice.movie_id order by boxoffice.rating desc;
