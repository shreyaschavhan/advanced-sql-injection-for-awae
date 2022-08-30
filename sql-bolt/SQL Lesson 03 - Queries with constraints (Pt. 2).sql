-- Questions:

-- Find all the Toy Story movies ✓
-- Find all the movies directed by John Lasseter ✓
-- Find all the movies (and director) not directed by John Lasseter ✓
-- Find all the WALL-* movies ✓

select title from movies where title like "Toy story%";
select title from movies where director = "John Lasseter";
select title, director from movies where director != "John Lasseter";
select * from movies where title like "wall-%";
