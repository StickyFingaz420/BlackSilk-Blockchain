import { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { 
  Shield, 
  Upload, 
  DollarSign, 
  Package, 
  MapPin, 
  Clock,
  Image as ImageIcon,
  X,
  Plus,
  AlertTriangle
} from 'lucide-react';
import { useAuth } from '@/hooks';
import { marketplaceAPI } from '@/lib/api';

export default function SellPage() {
  const router = useRouter();
  const { isAuthenticated } = useAuth();
  
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    category: 'digital',
    subcategory: '',
    price: '',
    quantity_available: '1',
    ships_from: '',
    ships_to: ['Worldwide'],
    shipping_price: '0',
    processing_time: '1-3 days',
  });

  const [images, setImages] = useState<File[]>([]);
  const [imageUrls, setImageUrls] = useState<string[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const categories = [
    { id: 'digital', name: 'Digital Goods', subcategories: ['Software', 'E-books', 'Courses', 'Digital Art'] },
    { id: 'services', name: 'Services', subcategories: ['Consulting', 'Design', 'Writing', 'Programming'] },
    { id: 'physical', name: 'Physical Goods', subcategories: ['Electronics', 'Clothing', 'Books', 'Supplies'] },
  ];

  const shippingRegions = [
    'Worldwide',
    'North America',
    'Europe',
    'Asia',
    'Australia',
    'South America',
    'Africa',
    'Local Only',
  ];

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    if (files.length + images.length > 5) {
      setError('Maximum 5 images allowed');
      return;
    }

    // Validate image files
    const validFiles = files.filter(file => {
      if (!file.type.startsWith('image/')) {
        setError('Only image files are allowed');
        return false;
      }
      if (file.size > 5 * 1024 * 1024) {
        setError('Images must be less than 5MB');
        return false;
      }
      return true;
    });

    setImages(prev => [...prev, ...validFiles]);
    
    // Create preview URLs
    validFiles.forEach(file => {
      const url = URL.createObjectURL(file);
      setImageUrls(prev => [...prev, url]);
    });
  };

  const removeImage = (index: number) => {
    setImages(prev => prev.filter((_, i) => i !== index));
    URL.revokeObjectURL(imageUrls[index]);
    setImageUrls(prev => prev.filter((_, i) => i !== index));
  };

  const handleShippingRegionChange = (region: string, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      ships_to: checked 
        ? [...prev.ships_to, region]
        : prev.ships_to.filter(r => r !== region)
    }));
  };

  const validateForm = (): boolean => {
    if (!formData.title.trim()) {
      setError('Product title is required');
      return false;
    }
    if (!formData.description.trim()) {
      setError('Product description is required');
      return false;
    }
    if (!formData.price || parseFloat(formData.price) <= 0) {
      setError('Valid price is required');
      return false;
    }
    if (parseInt(formData.quantity_available) <= 0) {
      setError('Valid quantity is required');
      return false;
    }
    if (formData.category === 'physical' && !formData.ships_from.trim()) {
      setError('Shipping location is required for physical goods');
      return false;
    }
    if (images.length === 0) {
      setError('At least one image is required');
      return false;
    }

    // Content moderation check
    const content = `${formData.title} ${formData.description}`.toLowerCase();
    const forbiddenTerms = ['porn', 'sex', 'adult', 'xxx', 'escort'];
    for (const term of forbiddenTerms) {
      if (content.includes(term)) {
        setError('Content violates community standards. Don\'t be sick.');
        return false;
      }
    }

    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!isAuthenticated) {
      setError('Please login to create a product listing');
      return;
    }

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);

    try {
      // Upload images to IPFS
      const imageHashes: string[] = [];
      for (const image of images) {
        const response = await marketplaceAPI.uploadImage(image);
        if (response.success && response.data) {
          imageHashes.push(response.data);
        } else {
          throw new Error('Failed to upload image');
        }
      }

      // Create product
      const productData = {
        ...formData,
        price: parseFloat(formData.price),
        quantity_available: parseInt(formData.quantity_available),
        shipping_price: parseFloat(formData.shipping_price),
        image_files: imageHashes, // Send IPFS hashes
      };

      const response = await marketplaceAPI.createProduct(productData);
      
      if (response.success) {
        setSuccess(true);
        setTimeout(() => {
          router.push(`/product/${response.data?.id}`);
        }, 2000);
      } else {
        setError(response.error || 'Failed to create product');
      }
    } catch (err) {
      setError('An error occurred while creating the product');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-silk-gradient flex items-center justify-center px-4">
        <div className="silk-card max-w-md text-center">
          <Shield className="h-16 w-16 text-silk-accent mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-silk-text mb-4">Login Required</h2>
          <p className="text-silk-muted mb-6">
            You need to access your wallet to create product listings.
          </p>
          <Link href="/login" className="silk-button w-full">
            Login to Continue
          </Link>
        </div>
      </div>
    );
  }

  if (success) {
    return (
      <div className="min-h-screen bg-silk-gradient flex items-center justify-center px-4">
        <div className="silk-card max-w-md text-center">
          <Package className="h-16 w-16 text-silk-success mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-silk-text mb-4">Product Created!</h2>
          <p className="text-silk-muted mb-6">
            Your product has been successfully listed on the marketplace.
          </p>
          <div className="loading-spinner mx-auto"></div>
          <p className="text-sm text-silk-muted mt-2">Redirecting to product page...</p>
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>Sell Product - BlackSilk Marketplace</title>
        <meta name="description" content="List your products on the decentralized BlackSilk marketplace" />
      </Head>

      <div className="min-h-screen bg-silk-gradient">
        {/* Header */}
        <header className="silk-nav">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <Link href="/" className="flex items-center space-x-2">
                <Shield className="h-8 w-8 text-silk-accent" />
                <span className="text-xl font-bold text-silk-text">BlackSilk</span>
              </Link>
              <Link href="/" className="text-silk-muted hover:text-silk-accent">
                ← Back to Marketplace
              </Link>
            </div>
          </div>
        </header>

        <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Page Header */}
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-silk-text mb-4">
              List Your Product
            </h1>
            <p className="text-xl text-silk-muted max-w-2xl mx-auto">
              Create a secure listing with automatic escrow protection
            </p>
          </div>

          {/* Community Warning */}
          <div className="community-warning mb-8">
            <AlertTriangle className="h-5 w-5 inline-block mr-2" />
            <strong>Community Standards:</strong> Don't be sick. 
            No pornographic, illegal, or inappropriate content allowed.
          </div>

          {/* Main Form */}
          <div className="silk-card">
            <form onSubmit={handleSubmit} className="space-y-8">
              {/* Basic Information */}
              <section>
                <h2 className="text-2xl font-bold text-silk-text mb-6">Basic Information</h2>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="md:col-span-2">
                    <label className="block text-sm font-medium text-silk-text mb-2">
                      Product Title *
                    </label>
                    <input
                      type="text"
                      name="title"
                      value={formData.title}
                      onChange={handleInputChange}
                      placeholder="Enter a descriptive title"
                      className="silk-input w-full"
                      maxLength={100}
                      required
                    />
                  </div>

                  <div className="md:col-span-2">
                    <label className="block text-sm font-medium text-silk-text mb-2">
                      Description *
                    </label>
                    <textarea
                      name="description"
                      value={formData.description}
                      onChange={handleInputChange}
                      placeholder="Describe your product in detail"
                      className="silk-input w-full h-32 resize-none"
                      maxLength={2000}
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-silk-text mb-2">
                      Category *
                    </label>
                    <select
                      name="category"
                      value={formData.category}
                      onChange={handleInputChange}
                      className="silk-input w-full"
                      required
                    >
                      {categories.map(cat => (
                        <option key={cat.id} value={cat.id}>{cat.name}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-silk-text mb-2">
                      Subcategory
                    </label>
                    <select
                      name="subcategory"
                      value={formData.subcategory}
                      onChange={handleInputChange}
                      className="silk-input w-full"
                    >
                      <option value="">Select subcategory</option>
                      {categories
                        .find(cat => cat.id === formData.category)
                        ?.subcategories.map(sub => (
                          <option key={sub} value={sub}>{sub}</option>
                        ))}
                    </select>
                  </div>
                </div>
              </section>

              {/* Pricing */}
              <section>
                <h2 className="text-2xl font-bold text-silk-text mb-6">Pricing & Quantity</h2>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div>
                    <label className="block text-sm font-medium text-silk-text mb-2">
                      Price (BLK) *
                    </label>
                    <div className="relative">
                      <DollarSign className="absolute left-3 top-1/2 transform -translate-y-1/2 text-silk-muted h-4 w-4" />
                      <input
                        type="number"
                        name="price"
                        value={formData.price}
                        onChange={handleInputChange}
                        placeholder="0.00"
                        className="silk-input w-full pl-10"
                        step="0.001"
                        min="0"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-silk-text mb-2">
                      Quantity Available *
                    </label>
                    <input
                      type="number"
                      name="quantity_available"
                      value={formData.quantity_available}
                      onChange={handleInputChange}
                      placeholder="1"
                      className="silk-input w-full"
                      min="1"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-silk-text mb-2">
                      Shipping Price (BLK)
                    </label>
                    <input
                      type="number"
                      name="shipping_price"
                      value={formData.shipping_price}
                      onChange={handleInputChange}
                      placeholder="0.00"
                      className="silk-input w-full"
                      step="0.001"
                      min="0"
                    />
                  </div>
                </div>
              </section>

              {/* Shipping (for physical goods) */}
              {formData.category === 'physical' && (
                <section>
                  <h2 className="text-2xl font-bold text-silk-text mb-6">Shipping Information</h2>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-medium text-silk-text mb-2">
                        Ships From *
                      </label>
                      <div className="relative">
                        <MapPin className="absolute left-3 top-1/2 transform -translate-y-1/2 text-silk-muted h-4 w-4" />
                        <input
                          type="text"
                          name="ships_from"
                          value={formData.ships_from}
                          onChange={handleInputChange}
                          placeholder="Country/Region"
                          className="silk-input w-full pl-10"
                          required
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-silk-text mb-2">
                        Processing Time
                      </label>
                      <div className="relative">
                        <Clock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-silk-muted h-4 w-4" />
                        <select
                          name="processing_time"
                          value={formData.processing_time}
                          onChange={handleInputChange}
                          className="silk-input w-full pl-10"
                        >
                          <option value="1-3 days">1-3 days</option>
                          <option value="3-5 days">3-5 days</option>
                          <option value="1 week">1 week</option>
                          <option value="2 weeks">2 weeks</option>
                          <option value="1 month">1 month</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6">
                    <label className="block text-sm font-medium text-silk-text mb-3">
                      Ships To
                    </label>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {shippingRegions.map(region => (
                        <label key={region} className="flex items-center space-x-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={formData.ships_to.includes(region)}
                            onChange={(e) => handleShippingRegionChange(region, e.target.checked)}
                            className="rounded border-silk-gray bg-silk-gray text-silk-accent focus:ring-silk-accent"
                          />
                          <span className="text-sm text-silk-text">{region}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                </section>
              )}

              {/* Images */}
              <section>
                <h2 className="text-2xl font-bold text-silk-text mb-6">Product Images</h2>
                
                <div className="space-y-4">
                  <div className="flex items-center justify-center w-full">
                    <label className="flex flex-col items-center justify-center w-full h-64 border-2 border-silk-gray border-dashed rounded-lg cursor-pointer hover:border-silk-accent transition-colors">
                      <div className="flex flex-col items-center justify-center pt-5 pb-6">
                        <Upload className="w-10 h-10 text-silk-muted mb-3" />
                        <p className="mb-2 text-sm text-silk-muted">
                          <span className="font-semibold">Click to upload</span> or drag and drop
                        </p>
                        <p className="text-xs text-silk-muted">PNG, JPG, GIF up to 5MB (Max 5 images)</p>
                      </div>
                      <input
                        type="file"
                        multiple
                        accept="image/*"
                        onChange={handleImageUpload}
                        className="hidden"
                      />
                    </label>
                  </div>

                  {/* Image Previews */}
                  {images.length > 0 && (
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                      {imageUrls.map((url, index) => (
                        <div key={index} className="relative group">
                          <img
                            src={url}
                            alt={`Preview ${index + 1}`}
                            className="w-full h-24 object-cover rounded-lg"
                          />
                          <button
                            type="button"
                            onClick={() => removeImage(index)}
                            className="absolute -top-2 -right-2 bg-silk-warning text-white rounded-full p-1 opacity-0 group-hover:opacity-100 transition-opacity"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </section>

              {/* Error Message */}
              {error && (
                <div className="bg-silk-warning/20 border border-silk-warning/50 text-silk-warning p-4 rounded-lg">
                  {error}
                </div>
              )}

              {/* Submit Button */}
              <div className="flex justify-end space-x-4">
                <Link href="/" className="silk-button-secondary">
                  Cancel
                </Link>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="silk-button flex items-center"
                >
                  {isSubmitting ? (
                    <div className="loading-spinner mr-2" />
                  ) : (
                    <Package className="h-4 w-4 mr-2" />
                  )}
                  {isSubmitting ? 'Creating...' : 'Create Listing'}
                </button>
              </div>
            </form>
          </div>
        </main>
      </div>
    </>
  );
}
