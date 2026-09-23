import { useState, useEffect } from 'react';
import { marketplaceAPI } from '@/lib/api';
import { Product, User, Order, NodeInfo, Balance, WebSocketMessage, CartItem, NodeStatus, ApiResponse } from '@/types';

// Authentication Hook
export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    checkAuthentication();
  }, []);

  const checkAuthentication = async () => {
    try {
      const credentials = localStorage.getItem('blacksilk_credentials');
      if (credentials) {
        const parsed = JSON.parse(credentials);
        // Verify credentials with server
        setIsAuthenticated(true);
        // TODO: Fetch user data
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (privateKey: string, recoveryPhrase?: string) => {
    setIsLoading(true);
    try {
      const response = await marketplaceAPI.login(privateKey, recoveryPhrase);
      if (response.success && response.data) {
        setUser(response.data);
        setIsAuthenticated(true);
        return { success: true };
      }
      return { success: false, error: response.error };
    } catch (error) {
      return { success: false, error: 'Login failed' };
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    marketplaceAPI.logout();
    setUser(null);
    setIsAuthenticated(false);
  };

  return {
    user,
    isLoading,
    isAuthenticated,
    login,
    logout,
  };
}

// Products Hook
export function useProducts(filters?: any) {
  const [products, setProducts] = useState<Product[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchProducts();
  }, [filters]);

  const fetchProducts = async () => {
    try {
      setIsLoading(true);
      const response = await marketplaceAPI.getProducts(filters);
      if (response.success && response.data) {
        setProducts(response.data);
        setError(null);
      } else {
        setError(response.error || 'Failed to fetch products');
      }
    } catch (err) {
      setError('An error occurred while fetching products');
    } finally {
      setIsLoading(false);
    }
  };

  const searchProducts = async (query: string) => {
    try {
      setIsLoading(true);
      const response = await marketplaceAPI.searchProducts(query, filters);
      if (response.success && response.data) {
        setProducts(response.data);
        setError(null);
      } else {
        setError(response.error || 'Search failed');
      }
    } catch (err) {
      setError('Search error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return {
    products,
    isLoading,
    error,
    refetch: fetchProducts,
    search: searchProducts,
  };
}

// Single Product Hook
export function useProduct(id: string) {
  const [product, setProduct] = useState<Product | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      fetchProduct();
    }
  }, [id]);

  const fetchProduct = async () => {
    try {
      setIsLoading(true);
      const response = await marketplaceAPI.getProduct(id);
      if (response.success && response.data) {
        setProduct(response.data);
        setError(null);
      } else {
        setError(response.error || 'Product not found');
      }
    } catch (err) {
      setError('Failed to fetch product');
    } finally {
      setIsLoading(false);
    }
  };

  return {
    product,
    isLoading,
    error,
    refetch: fetchProduct,
  };
}

// Orders Hook
export function useOrders() {
  const [orders, setOrders] = useState<Order[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchOrders();
  }, []);

  const fetchOrders = async () => {
    try {
      setIsLoading(true);
      const response = await marketplaceAPI.getOrders();
      if (response.success && response.data) {
        setOrders(response.data);
        setError(null);
      } else {
        setError(response.error || 'Failed to fetch orders');
      }
    } catch (err) {
      setError('Error fetching orders');
    } finally {
      setIsLoading(false);
    }
  };

  const createOrder = async (orderData: any) => {
    try {
      const response = await marketplaceAPI.createOrder(orderData);
      if (response.success) {
        await fetchOrders(); // Refresh orders
        return { success: true, data: response.data };
      }
      return { success: false, error: response.error };
    } catch (err) {
      return { success: false, error: 'Failed to create order' };
    }
  };

  return {
    orders,
    isLoading,
    error,
    createOrder,
    refetch: fetchOrders,
  };
}

// Node Status Hook
export function useNodeStatus() {
  const [nodeInfo, setNodeInfo] = useState<NodeInfo | null>(null);
  const [isOnline, setIsOnline] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchNodeStatus();
    const interval = setInterval(fetchNodeStatus, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchNodeStatus = async () => {
    try {
      const response = await marketplaceAPI.getNodeInfo();
      if (response.success && response.data) {
        setNodeInfo(response.data);
        setIsOnline(true);
      } else {
        setIsOnline(false);
      }
    } catch (err) {
      setIsOnline(false);
    } finally {
      setIsLoading(false);
    }
  };

  return {
    nodeInfo,
    isOnline,
    isLoading,
  };
}

// Balance Hook
export function useBalance(publicKey?: string) {
  const [balance, setBalance] = useState<Balance | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (publicKey) {
      fetchBalance();
    }
  }, [publicKey]);

  const fetchBalance = async () => {
    if (!publicKey) return;

    try {
      setIsLoading(true);
      const response: ApiResponse<Balance> = await marketplaceAPI.getBalance(publicKey);
      if (response.success && response.data) {
        setBalance(response.data);
        setError(null);
      } else {
        setError(response.error || 'Failed to fetch balance');
      }
    } catch (err) {
      setError('Error fetching balance');
    } finally {
      setIsLoading(false);
    }
  };

  return {
    balance,
    isLoading,
    error,
    refetch: fetchBalance,
  };
}

// WebSocket Hook
export function useWebSocket() {
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [ws, setWs] = useState<WebSocket | null>(null);

  useEffect(() => {
    const websocket = marketplaceAPI.connectWebSocket((message: WebSocketMessage) => {
      setMessages(prev => [...prev.slice(-99), message]); // Keep last 100 messages
    });

    if (websocket) {
      setWs(websocket);
      websocket.onopen = () => setIsConnected(true);
      websocket.onclose = () => setIsConnected(false);
      websocket.onerror = () => setIsConnected(false);
    }

    return () => {
      if (websocket) {
        websocket.close();
      }
    };
  }, []);

  const sendMessage = (message: any) => {
    if (ws && isConnected) {
      ws.send(JSON.stringify(message));
    }
  };

  return {
    messages,
    isConnected,
    sendMessage,
  };
}

// Local Storage Hook
export function useLocalStorage<T>(key: string, initialValue: T) {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      return initialValue;
    }
  });

  const setValue = (value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
    } catch (error) {
      console.error('Error saving to localStorage:', error);
    }
  };

  return [storedValue, setValue] as const;
}

// Shopping Cart Hook
export function useCart() {
  const [cart, setCart] = useLocalStorage<CartItem[]>('blacksilk_cart', []);

  const addToCart = (product: Product, quantity: number = 1) => {
    setCart(currentCart => {
      const existingItemIndex = currentCart.findIndex(
        item => item.productId === product.id && item.seller === product.seller
      );

      if (existingItemIndex >= 0) {
        const updatedCart = [...currentCart];
        updatedCart[existingItemIndex].quantity += quantity;
        return updatedCart;
      }

      const newItem: CartItem = {
        productId: product.id,
        title: product.title,
        price: product.price,
        quantity,
        seller: product.seller,
        image: product.images?.[0],
        category: product.category
      };

      return [...currentCart, newItem];
    });
  };

  const removeFromCart = (productId: string, seller: string) => {
    setCart(currentCart => 
      currentCart.filter(item => 
        !(item.productId === productId && item.seller === seller)
      )
    );
  };

  const updateQuantity = (productId: string, seller: string, quantity: number) => {
    if (quantity <= 0) {
      removeFromCart(productId, seller);
      return;
    }

    setCart(currentCart => 
      currentCart.map(item => 
        item.productId === productId && item.seller === seller
          ? { ...item, quantity }
          : item
      )
    );
  };

  const clearCart = () => {
    setCart([]);
  };

  const getTotalAmount = () => {
    return cart.reduce((total, item) => total + (item.price * item.quantity), 0);
  };

  const getTotalItems = () => {
    return cart.reduce((total, item) => total + item.quantity, 0);
  };

  const isInCart = (productId: string, seller: string) => {
    return cart.some(item => item.productId === productId && item.seller === seller);
  };

  const getCartItem = (productId: string, seller: string) => {
    return cart.find(item => item.productId === productId && item.seller === seller);
  };

  return {
    cart,
    items: cart, // Alias for backward compatibility
    addToCart,
    removeFromCart,
    updateQuantity,
    clearCart,
    getTotalAmount,
    total: getTotalAmount(), // Alias for backward compatibility
    getTotalItems,
    isInCart,
    getCartItem
  };
}
