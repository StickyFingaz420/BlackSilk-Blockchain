import React, { useState, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  TextField,
  Typography,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Grid,
  InputAdornment,
  IconButton,
  Alert,
  FormHelperText,
  Autocomplete,
} from '@mui/material';
import { useDropzone } from 'react-dropzone';
import { Category, ItemCondition, ShippingOption, Listing } from '../types';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import ImageIcon from '@mui/icons-material/Image';
import { uploadToIPFS } from '../utils/ipfs';

const SUBCATEGORIES: Record<Category, string[]> = {
  [Category.Electronics]: ['Computers', 'Phones', 'Audio', 'Gaming', 'Accessories'],
  [Category.Fashion]: ['Men', 'Women', 'Accessories', 'Shoes', 'Jewelry'],
  [Category.Home]: ['Furniture', 'Decor', 'Kitchen', 'Garden', 'Lighting'],
  [Category.Art]: ['Paintings', 'Sculptures', 'Prints', 'Digital Art', 'Photography'],
  [Category.Collectibles]: ['Cards', 'Coins', 'Stamps', 'Memorabilia', 'Antiques'],
  [Category.Books]: ['Fiction', 'Non-Fiction', 'Academic', 'Comics', 'Magazines'],
  [Category.Sports]: ['Equipment', 'Apparel', 'Accessories', 'Memorabilia'],
  [Category.Health]: ['Supplements', 'Equipment', 'Personal Care'],
  [Category.Beauty]: ['Skincare', 'Makeup', 'Haircare', 'Fragrances'],
  [Category.Automotive]: ['Parts', 'Accessories', 'Tools', 'Car Care'],
  [Category.Other]: ['Miscellaneous'],
};

interface ListingFormProps {
  initialData?: Partial<Listing>;
  onSubmit: (data: Partial<Listing>) => Promise<void>;
}

export default function ListingForm({ initialData, onSubmit }: ListingFormProps) {
  const [formData, setFormData] = useState<Partial<Listing>>({
    title: '',
    description: '',
    price: 0,
    category: Category.Other,
    subcategory: '',
    tags: [],
    condition: ItemCondition.New,
    shipping: [],
    location: '',
    quantity: 1,
    images: [],
    ...initialData,
  });

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [newTag, setNewTag] = useState('');
  const [newShipping, setNewShipping] = useState<Partial<ShippingOption>>({
    method: '',
    price: 0,
    estimated_days: 1,
    regions: [],
  });

  // Image upload handling
  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    try {
      const uploadedHashes: string[] = [];
      for (const file of acceptedFiles) {
        // Show a loading indicator if desired
        const cid = await uploadToIPFS(file);
        uploadedHashes.push(cid); // Store just the CID, not the gateway URL
      }
      handleChange('images', [...(formData.images || []), ...uploadedHashes]);
    } catch (err) {
      setError('Failed to upload image to IPFS');
    }
  }, [formData.images]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'image/*': ['.jpeg', '.jpg', '.png', '.gif', '.webp']
    },
    maxSize: 5242880, // 5MB
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      // Validate form
      if (!formData.title || !formData.description || !formData.price) {
        throw new Error('Please fill in all required fields');
      }

      await onSubmit(formData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (field: keyof Listing, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  const addTag = () => {
    if (newTag && !formData.tags?.includes(newTag)) {
      handleChange('tags', [...(formData.tags || []), newTag]);
      setNewTag('');
    }
  };

  const removeTag = (tag: string) => {
    handleChange('tags', formData.tags?.filter(t => t !== tag));
  };

  const addShipping = () => {
    if (newShipping.method && newShipping.price) {
      handleChange('shipping', [...(formData.shipping || []), newShipping]);
      setNewShipping({ method: '', price: 0, estimated_days: 1, regions: [] });
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <Card>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            {initialData ? 'Edit Listing' : 'Create New Listing'}
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Grid container spacing={3}>
            {/* Basic Information */}
            <Grid item xs={12}>
              <TextField
                fullWidth
                required
                label="Title"
                value={formData.title}
                onChange={(e) => handleChange('title', e.target.value)}
              />
            </Grid>

            <Grid item xs={12}>
              <TextField
                fullWidth
                required
                multiline
                rows={4}
                label="Description"
                value={formData.description}
                onChange={(e) => handleChange('description', e.target.value)}
              />
            </Grid>

            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                required
                type="number"
                label="Price (BLK)"
                value={formData.price}
                onChange={(e) => handleChange('price', parseFloat(e.target.value))}
                InputProps={{
                  startAdornment: <InputAdornment position="start">₿</InputAdornment>,
                }}
              />
            </Grid>

            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                required
                type="number"
                label="Quantity"
                value={formData.quantity}
                onChange={(e) => handleChange('quantity', parseInt(e.target.value))}
              />
            </Grid>

            {/* Category Selection */}
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Category</InputLabel>
                <Select
                  value={formData.category}
                  onChange={(e) => handleChange('category', e.target.value)}
                >
                  {Object.values(Category).map((cat) => (
                    <MenuItem key={cat} value={cat}>
                      {cat}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Subcategory</InputLabel>
                <Select
                  value={formData.subcategory}
                  onChange={(e) => handleChange('subcategory', e.target.value)}
                >
                  {SUBCATEGORIES[formData.category as Category]?.map((sub) => (
                    <MenuItem key={sub} value={sub}>
                      {sub}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Condition */}
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Condition</InputLabel>
                <Select
                  value={formData.condition}
                  onChange={(e) => handleChange('condition', e.target.value)}
                >
                  {Object.values(ItemCondition).map((cond) => (
                    <MenuItem key={cond} value={cond}>
                      {cond}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Location */}
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Location"
                value={formData.location}
                onChange={(e) => handleChange('location', e.target.value)}
              />
            </Grid>

            {/* Tags */}
            <Grid item xs={12}>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Tags
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
                  {formData.tags?.map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      onDelete={() => removeTag(tag)}
                    />
                  ))}
                </Box>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <TextField
                    size="small"
                    value={newTag}
                    onChange={(e) => setNewTag(e.target.value)}
                    placeholder="Add a tag"
                  />
                  <Button
                    variant="outlined"
                    onClick={addTag}
                    startIcon={<AddIcon />}
                  >
                    Add
                  </Button>
                </Box>
              </Box>
            </Grid>

            {/* Image Upload */}
            <Grid item xs={12}>
              <Box
                {...getRootProps()}
                sx={{
                  border: '2px dashed',
                  borderColor: isDragActive ? 'primary.main' : 'grey.300',
                  borderRadius: 1,
                  p: 3,
                  textAlign: 'center',
                  cursor: 'pointer',
                  mb: 2,
                }}
              >
                <input {...getInputProps()} />
                <ImageIcon sx={{ fontSize: 48, color: 'grey.500', mb: 1 }} />
                <Typography>
                  {isDragActive
                    ? 'Drop the files here...'
                    : 'Drag & drop images here, or click to select files'}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Maximum file size: 5MB. Supported formats: JPG, PNG, GIF, WebP
                </Typography>
              </Box>
              {/* Show image previews */}
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mt: 1 }}>
                {(formData.images || []).map((img, idx) => (
                  <Box key={idx} sx={{ width: 80, height: 80, border: '1px solid #eee', borderRadius: 1, overflow: 'hidden', position: 'relative' }}>
                    <img src={img} alt={`Listing image ${idx + 1}`} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                    <IconButton
                      size="small"
                      sx={{ position: 'absolute', top: 2, right: 2, background: 'rgba(255,255,255,0.7)' }}
                      onClick={() => handleChange('images', formData.images?.filter((_, i) => i !== idx))}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Box>
                ))}
              </Box>
            </Grid>

            {/* Shipping Options */}
            <Grid item xs={12}>
              <Typography variant="subtitle1" gutterBottom>
                Shipping Options
              </Typography>
              {formData.shipping?.map((option, index) => (
                <Box key={index} sx={{ mb: 2, p: 2, border: '1px solid', borderColor: 'grey.300', borderRadius: 1 }}>
                  <Typography variant="subtitle2">
                    {option.method} - {option.price} BLK
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Estimated delivery: {option.estimated_days} days
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Regions: {option.regions.join(', ')}
                  </Typography>
                  <IconButton
                    size="small"
                    onClick={() => handleChange('shipping', formData.shipping?.filter((_, i) => i !== index))}
                  >
                    <DeleteIcon />
                  </IconButton>
                </Box>
              ))}
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
                <TextField
                  size="small"
                  label="Method"
                  value={newShipping.method}
                  onChange={(e) => setNewShipping(prev => ({ ...prev, method: e.target.value }))}
                />
                <TextField
                  size="small"
                  type="number"
                  label="Price (BLK)"
                  value={newShipping.price}
                  onChange={(e) => setNewShipping(prev => ({ ...prev, price: parseFloat(e.target.value) }))}
                />
                <TextField
                  size="small"
                  type="number"
                  label="Days"
                  value={newShipping.estimated_days}
                  onChange={(e) => setNewShipping(prev => ({ ...prev, estimated_days: parseInt(e.target.value) }))}
                />
                <Button
                  variant="outlined"
                  onClick={addShipping}
                  startIcon={<AddIcon />}
                >
                  Add
                </Button>
              </Box>
            </Grid>

            {/* Submit Button */}
            <Grid item xs={12}>
              <Button
                type="submit"
                variant="contained"
                color="primary"
                size="large"
                fullWidth
                disabled={loading}
              >
                {loading ? 'Saving...' : initialData ? 'Update Listing' : 'Create Listing'}
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    </form>
  );
}