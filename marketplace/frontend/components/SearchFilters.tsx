import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Slider,
  Typography,
  Button,
  Chip,
  Grid,
  InputAdornment,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import FilterListIcon from '@mui/icons-material/FilterList';
import { Category, ItemCondition, SortOption } from '../types';
import type { SearchFilters } from '../types';

interface SearchFiltersProps {
  onSearch: (filters: SearchFilters) => void;
  initialFilters?: Partial<SearchFilters>;
}

export default function SearchFilters({ onSearch, initialFilters }: SearchFiltersProps) {
  const [filters, setFilters] = useState<SearchFilters>({
    query: '',
    category: undefined,
    subcategory: undefined,
    minPrice: undefined,
    maxPrice: undefined,
    condition: undefined,
    location: '',
    sortBy: SortOption.RecentlyListed,
    page: 1,
    limit: 10,
    ...initialFilters,
  });

  const [priceRange, setPriceRange] = useState<[number, number]>([0, 1000]);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    onSearch(filters);
  }, [filters, onSearch]);

  const handleChange = (field: keyof SearchFilters, value: any) => {
    setFilters(prev => ({
      ...prev,
      [field]: value,
      // Reset page when filters change
      page: field === 'page' ? value : 1,
    }));
  };

  const handlePriceChange = (_event: Event, newValue: number | number[]) => {
    const [min, max] = newValue as number[];
    setPriceRange([min, max]);
    handleChange('minPrice', min);
    handleChange('maxPrice', max);
  };

  const clearFilters = () => {
    setFilters({
      query: '',
      category: undefined,
      subcategory: undefined,
      minPrice: undefined,
      maxPrice: undefined,
      condition: undefined,
      location: '',
      sortBy: SortOption.RecentlyListed,
      page: 1,
      limit: 10,
    });
    setPriceRange([0, 1000]);
  };

  return (
    <Box sx={{ mb: 4 }}>
      {/* Basic Search */}
      <Grid container spacing={2} alignItems="flex-start">
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            placeholder="Search listings..."
            value={filters.query}
            onChange={(e) => handleChange('query', e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />
        </Grid>

        <Grid item xs={12} md={3}>
          <FormControl fullWidth>
            <InputLabel>Category</InputLabel>
            <Select
              value={filters.category || ''}
              onChange={(e) => handleChange('category', e.target.value)}
            >
              <MenuItem value="">All Categories</MenuItem>
              {Object.values(Category).map((cat) => (
                <MenuItem key={cat} value={cat}>
                  {cat}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>

        <Grid item xs={12} md={3}>
          <FormControl fullWidth>
            <InputLabel>Sort By</InputLabel>
            <Select
              value={filters.sortBy}
              onChange={(e) => handleChange('sortBy', e.target.value)}
            >
              {Object.entries(SortOption).map(([key, value]) => (
                <MenuItem key={value} value={value}>
                  {key.replace(/([A-Z])/g, ' $1').trim()}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
      </Grid>

      {/* Advanced Filters */}
      <Box sx={{ mt: 2 }}>
        <Button
          startIcon={<FilterListIcon />}
          onClick={() => setShowAdvanced(!showAdvanced)}
          sx={{ mb: 2 }}
        >
          {showAdvanced ? 'Hide Advanced Filters' : 'Show Advanced Filters'}
        </Button>

        {showAdvanced && (
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography gutterBottom>Price Range (BLK)</Typography>
              <Box sx={{ px: 2 }}>
                <Slider
                  value={priceRange}
                  onChange={handlePriceChange}
                  valueLabelDisplay="auto"
                  min={0}
                  max={1000}
                  step={10}
                />
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
                  <Typography variant="body2">₿{priceRange[0]}</Typography>
                  <Typography variant="body2">₿{priceRange[1]}</Typography>
                </Box>
              </Box>
            </Grid>

            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Condition</InputLabel>
                <Select
                  value={filters.condition || ''}
                  onChange={(e) => handleChange('condition', e.target.value)}
                >
                  <MenuItem value="">Any Condition</MenuItem>
                  {Object.values(ItemCondition).map((cond) => (
                    <MenuItem key={cond} value={cond}>
                      {cond}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Location"
                value={filters.location}
                onChange={(e) => handleChange('location', e.target.value)}
                placeholder="Enter location..."
              />
            </Grid>

            <Grid item xs={12}>
              <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                <Button variant="outlined" onClick={clearFilters}>
                  Clear Filters
                </Button>
              </Box>
            </Grid>
          </Grid>
        )}

        {/* Active Filters */}
        {(filters.category || filters.condition || filters.location || filters.minPrice) && (
          <Box sx={{ mt: 2, display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {filters.category && (
              <Chip
                label={`Category: ${filters.category}`}
                onDelete={() => handleChange('category', undefined)}
              />
            )}
            {filters.condition && (
              <Chip
                label={`Condition: ${filters.condition}`}
                onDelete={() => handleChange('condition', undefined)}
              />
            )}
            {filters.location && (
              <Chip
                label={`Location: ${filters.location}`}
                onDelete={() => handleChange('location', '')}
              />
            )}
            {(filters.minPrice || filters.maxPrice) && (
              <Chip
                label={`Price: ₿${filters.minPrice || 0} - ₿${filters.maxPrice || '∞'}`}
                onDelete={() => {
                  handleChange('minPrice', undefined);
                  handleChange('maxPrice', undefined);
                  setPriceRange([0, 1000]);
                }}
              />
            )}
          </Box>
        )}
      </Box>
    </Box>
  );
}