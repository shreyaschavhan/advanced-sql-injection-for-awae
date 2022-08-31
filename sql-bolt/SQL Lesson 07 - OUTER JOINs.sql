-- Find the list of all buildings that have employees ✓
-- Find the list of all buildings and their capacity ✓
-- List all buildings and the distinct employee roles in each building (including empty buildings) ✓

select distinct building_name from buildings left join employees on buildings.building_name = employees.building where building is not null;

select * from buildings; 
OR 
select distinct building_name, capacity from buildings left join employees on buildings.building_name = employees.building;

select distinct building_name, role from buildings left join employees on buildings.building_name = employees.building;

