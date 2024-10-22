<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Product;
use App\Models\ProductRequest;


/**
 * @OA\Schema(
 *     schema="Product",
 *     type="object",
 *     @OA\Property(property="id", type="integer"),
 *     @OA\Property(property="name", type="string"),
 *     @OA\Property(property="description", type="string"),
 *     @OA\Property(property="price", type="number", format="float"),
 *     @OA\Property(property="category_id", type="integer"),
 *     @OA\Property(property="stock", type="integer"),
 *     @OA\Property(property="image_path", type="string"),
 *     @OA\Property(property="is_featured", type="boolean"),
 * )
 */


class ProductController extends Controller
{


    /**
     * @OA\Get(
     *     path="/products",
     *     tags={"Products"},
     *     summary="Obtener lista de productos con filtros opcionales",
     *     @OA\Parameter(
     *         name="category_id",
     *         in="query",
     *         description="ID de la categoría",
     *         required=false,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="status",
     *         in="query",
     *         description="Estado del producto (available, unavailable, etc.)",
     *         required=false,
     *         @OA\Schema(
     *             type="string",
     *             enum={"available", "unavailable", "out of stock", "discontinued"},
     *             default="available"
     *         )
     *     ),
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Número de página para paginación",
     *         required=false,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Parameter(
     *         name="limit",
     *         in="query",
     *         description="Cantidad de productos por página",
     *         required=false,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Lista de productos obtenida exitosamente",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(ref="#/components/schemas/Product")
     *         )
     *     ),
     *     @OA\Response(response=404, description="No se encontraron productos")
     * )
     */


    public function index(Request $request)
    {
        $category_id = $request->query('category_id');
        $status = $request->query('status');
        $limit = $request->query('limit', 10);
        $page = $request->query('page', 1);

        $approvedRequests = ProductRequest::where('status', 'approved')->get();
        $approvedRequestIds = $approvedRequests->pluck('id');

        $query = Product::query();
        $query->whereIn('request_id', $approvedRequestIds);

        if ($category_id) {
            $query->where('category_id', $category_id);
        }
        if ($status) {
            $query->where('status', $status);
        }

        $products = $query->paginate($limit, ['*'], 'page', $page);

        if ($products->isEmpty()) {
            return response()->json(['message' => 'No products found'], 404);
        }

        $formattedProducts = $products->map(function ($product) use ($approvedRequests) {
            $approvedRequest = $approvedRequests->where('id', $product->request_id)->first();

            return [
                'id' => $product->id,
                'name' => $product->name,
                'description' => $product->description,
                'price' => $product->price,
                'category_id' => $product->category_id,
                'status' => $product->status,
                'user_id' => $product->user_id,
                'is_featured' => $product->is_featured,
                'stock' => $product->stock,
                'image_path' => $product->image_path,
                'created_at' => $product->created_at,
                'updated_at' => $product->updated_at,
                'request' => $approvedRequest ? [
                    'status' => $approvedRequest->status,
                    'admin_id' => $approvedRequest->admin_id,
                ] : null,
            ];
        });

        return response()->json(['message' => 'Product list retrieved successfully', 'product' => $formattedProducts], 200);
    }


    /**
     * @OA\Post(
     *     path="/products",
     *     tags={"Products"},
     *     summary="Crear producto",
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name", "description", "price", "category_id", "status", "stock", "is_featured"},
     *             @OA\Property(property="name", type="string", description="Nombre del producto"),
     *             @OA\Property(property="description", type="string", description="Descripción del producto"),
     *             @OA\Property(property="price", type="number", format="float", description="Precio del producto"),
     *             @OA\Property(property="category_id", type="integer", description="ID de la categoría"),
     *             @OA\Property(property="status", type="string", description="Estado del producto"),
     *             @OA\Property(property="stock", type="integer", description="Cantidad en stock"),
     *             @OA\Property(property="is_featured", type="boolean", description="¿Es un producto destacado?"),
     *             example={
     *                 "name": "Producto Ejemplo",
     *                 "description": "Descripción del producto ejemplo.",
     *                 "price": 99.99,
     *                 "category_id": 1,
     *                 "status": "disponible",
     *                 "stock": 100,
     *                 "is_featured": 1
     *             }
     *         )
     *     ),
     *     @OA\Response(response=201, description="Producto creado exitosamente"),
     *     @OA\Response(response=400, description="Los datos ingresados son incorrectos"),
     *     @OA\Response(response=422, description="Error de validación")
     * )
     */
    public function create(Request $request)
    {
        try {
            $this->validateProduct($request);
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json(['error' => $e->validator->errors()], 422);
        }

        $user = $request->user();

        if ($user->type_user != 2 && $user->type_user != 3) {
            return response()->json(['error' => 'No tienes los permisos para esta acción'], 403);
        }

        $productRequest = ProductRequest::create([
            'name' => $request->input('name'),
            'description' => $request->input('description'),
            'user_id' => $user->id,
            'status' => 'pending',
        ]);

        $status = $request->input('stock') > 0 ? 'available' : 'unavailable';

        $imagePath = null;
        if ($request->hasFile('image')) {
            $imagePath = $request->file('image')->store('products', 'public');
        }

        $product = Product::create([
            'name' => $request->input('name'),
            'description' => $request->input('description'),
            'price' => $request->input('price'),
            'category_id' => $request->input('category_id'),
            'status' => $status,
            'stock' => $request->input('stock'),
            'is_featured' => $request->input('is_featured', false),
            'user_id' => $user->id,
            'request_id' => $productRequest->id,
            'image_path' => $imagePath,
        ]);

        return response()->json($product, 201);
    }



    /**
     * @OA\Put(
     *     path="/products/{id}",
     *     tags={"Products"},
     *     summary="Actualizar producto",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer", description="ID del producto a actualizar")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name", "description", "price", "category_id", "status", "stock", "is_featured"},
     *             @OA\Property(property="name", type="string", description="Nombre del producto"),
     *             @OA\Property(property="description", type="string", description="Descripción del producto"),
     *             @OA\Property(property="price", type="number", format="float", description="Precio del producto"),
     *             @OA\Property(property="category_id", type="integer", description="ID de la categoría"),
     *             @OA\Property(property="status", type="string", description="Estado del producto"),
     *             @OA\Property(property="stock", type="integer", description="Cantidad en stock"),
     *             @OA\Property(property="is_featured", type="boolean", description="¿Es un producto destacado?"),
     *             example={
     *                 "name": "Producto Actualizado",
     *                 "description": "Descripción actualizada del producto.",
     *                 "price": 79.99,
     *                 "category_id": 2,
     *                 "stock": 50,
     *             }
     *         )
     *     ),
     *     @OA\Response(response=200, description="Producto actualizado exitosamente"),
     *     @OA\Response(response=404, description="Producto no encontrado"),
     *     @OA\Response(response=400, description="Los datos ingresados son incorrectos"),
     *     @OA\Response(response=422, description="Error de validación")
     * )
     */

    public function update(Request $request, $id)
    {
        $this->validateProduct($request);

        $product = Product::find($id);

        if (!$product) {
            return response()->json(['message' => 'Producto no encontrado'], 404);
        }

        $user = $request->user();

        if ($user->type_user != 3 && $product->user_id != $user->id) {
            return response()->json(['error' => 'Error de validación'], 403);
        }

        $product->update($request->all());

        return response()->json(['message' => 'Producto actualizado exitosamente', 'product' => $product]);
    }


    /**
     * @OA\Delete(
     *     path="/products/{id}",
     *     tags={"Products"},
     *     summary="Eliminar producto",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer", description="ID del producto a eliminar")
     *     ),
     *     @OA\Response(response=200, description="Producto eliminado exitosamente"),
     *     @OA\Response(response=404, description="Producto no encontrado"),
     *     @OA\Response(response=400, description="Error en la solicitud")
     * )
     */
    public function delete($id)
    {
        $product = Product::find($id);

        if (!$product) {
            return response()->json(['message' => 'Producto no encontrado.'], 404);
        }

        $user = request()->user();

        if ($user->type_user != 3 && $product->user_id != $user->id) {
            return response()->json(['error' => 'Error de autorización'], 403);
        }

        $product->delete();
        return response()->json(['message' => 'Producto eliminado exitosamente.']);
    }

    /**
     * @OA\Get(
     *     path="/products/requests/waitlist/",
     *     tags={"Products"},
     *     summary="Obtener los productos en lista de espera",
     *     security={{"bearerAuth": {}}},
     *     @OA\Response(response=201, description="Productos"),
     *     @OA\Response(response=403, description="No tiene permisos para acceder"),
     *     @OA\Response(response=422, description="Error")
     * )
     */

    public function getProductsInWaitlist(Request $request)
    {
        $authenticatedUser = $request->user();

        if ($authenticatedUser->type_user !== 3) {
            return response()->json(['message' => 'No tienes permiso para acceder a esta página.'], 403);
        }


        $pendingRequests = ProductRequest::where('status', 'pending')->get();

        return response()->json(['requests' => $pendingRequests], 200);
    }

    /**
     * @OA\Put(
     *     path="/products/requests/waitlist/{id}/approve",
     *     tags={"Products"},
     *     summary="Aprobar un producto en la lista de espera",
     *     description="Este endpoint permite a un administrador aprobar una solicitud de producto en la lista de espera. Solo los usuarios con el rol adecuado pueden acceder a esta acción.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="ID de la solicitud de producto que se desea aprobar.",
     *         @OA\Schema(type="integer")
     *     ),
     *  
     *     @OA\Response(response=200, description="Solicitud aprobada con éxito.", 
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Solicitud aprobada."),
     *         )
     *     ),
     *     @OA\Response(response=403, description="No tiene permiso para acceder a esta acción."),
     *     @OA\Response(response=404, description="Solicitud no encontrada o ya procesada."),
     *     @OA\Response(response=422, description="Error en la solicitud.")
     * )
     */


    public function approveRequest($id, Request $request)
    {
        $authenticatedUser = $request->user();

        if ($authenticatedUser->type_user !== 3) {
            return response()->json(['message' => 'No tienes permiso para acceder a esta acción.'], 403);
        }

        $requestToUpdate = ProductRequest::find($id);

        if (!$requestToUpdate || $requestToUpdate->status !== 'pending') {
            return response()->json(['message' => 'Solicitud no encontrada o ya procesada.'], 404);
        }

        $requestToUpdate->status = 'approved';
        $requestToUpdate->admin_id = $authenticatedUser->id;
        $requestToUpdate->save();

        return response()->json([
            'message' => 'Solicitud aprobada.',
            'request' => $requestToUpdate
        ], 200);
    }


    /**
     * @OA\Put(
     *     path="/products/requests/waitlist/{id}/reject",
     *     tags={"Products"},
     *     summary="Rechazar un producto en la lista de espera",
     *     description="Este endpoint permite a un administrador rechazar una solicitud de producto en la lista de espera. Solo los usuarios con el rol adecuado pueden acceder a esta acción.",
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="ID de la solicitud de producto que se desea rechazar.",
     *         @OA\Schema(type="integer")
     *     ),
     *     
     *     @OA\Response(response=200, description="Solicitud rechazada con éxito.", 
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Solicitud rechazada."),
     *         )
     *     ),
     *     @OA\Response(response=403, description="No tiene permiso para acceder a esta acción."),
     *     @OA\Response(response=404, description="Solicitud no encontrada o ya procesada."),
     *     @OA\Response(response=422, description="Error en la solicitud.")
     * )
     */


    public function rejectRequest($id, Request $request)
    {
        $authenticatedUser = $request->user();

        // Verificar si el usuario tiene permisos adecuados
        if ($authenticatedUser->type_user !== 3) {
            return response()->json(['message' => 'No tienes permiso para acceder a esta acción.'], 403);
        }

        // Buscar la solicitud de producto por ID
        $requestToUpdate = ProductRequest::find($id);

        // Verificar si la solicitud existe y está en estado 'pending'
        if (!$requestToUpdate || $requestToUpdate->status !== 'pending') {
            return response()->json(['message' => 'Solicitud no encontrada o ya procesada.'], 404);
        }

        // Actualizar el estado de la solicitud a 'rejected'
        $requestToUpdate->status = 'rejected';
        $requestToUpdate->admin_id = $authenticatedUser->id;
        $requestToUpdate->save();

        return response()->json([
            'message' => 'Solicitud rechazada.',
            'request' => $requestToUpdate
        ], 200);
    }

    private function validateProduct(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'description' => 'required|string|max:255',
            'price' => 'required|numeric',
            'category_id' => 'required|numeric',
            'stock' => 'required|numeric',
            'is_featured' => 'nullable|boolean',
        ]);
    }
}