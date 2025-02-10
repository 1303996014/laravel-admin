<?php

namespace Encore\Admin\Controllers;

use Encore\Admin\Form;
use Encore\Admin\Grid;
use Encore\Admin\Show;
use Encore\Admin\Facades\Admin;
use Illuminate\Support\MessageBag;
use Illuminate\Support\Facades\Hash;

class UserController extends AdminController
{
    /**
     * {@inheritdoc}
     */
    protected function title()
    {
        return trans('admin.administrator');
    }

    /**
     * Make a grid builder.
     *
     * @return Grid
     */
    protected function grid()
    {
        /**@var \Illuminate\Database\Eloquent\Model */
        $userModel = config('admin.database.users_model');

        $grid = new Grid(new $userModel());

        $grid->column('id', 'ID')->sortable();
        $grid->column('username', trans('admin.username'));
        $grid->column('name', trans('admin.name'));
        $grid->column('roles', trans('admin.roles'))->pluck('name')->label();
        $grid->column('created_at', trans('admin.created_at'));
        $grid->column('updated_at', trans('admin.updated_at'));

        $grid->actions(function (Grid\Displayers\Actions $actions) {
            if ($actions->getKey() == 1) {
                $actions->disableDelete();
            }
        });

        $grid->tools(function (Grid\Tools $tools) {
            $tools->batch(function (Grid\Tools\BatchActions $actions) {
                $actions->disableDelete();
            });
        });

        return $grid;
    }

    /**
     * Make a show builder.
     *
     * @param mixed $id
     *
     * @return Show
     */
    protected function detail($id)
    {
        $userModel = config('admin.database.users_model');

        $show = new Show($userModel::findOrFail($id));

        $show->field('id', 'ID');
        $show->field('username', trans('admin.username'));
        $show->field('name', trans('admin.name'));
        $show->field('roles', trans('admin.roles'))->as(function ($roles) {
            return $roles->pluck('name');
        })->label();
        $show->field('permissions', trans('admin.permissions'))->as(function ($permission) {
            return $permission->pluck('name');
        })->label();
        $show->field('created_at', trans('admin.created_at'));
        $show->field('updated_at', trans('admin.updated_at'));

        return $show;
    }

    /**
     * Make a form builder.
     *
     * @return Form
     */
    public function form()
    {
        /**@var \Illuminate\Database\Eloquent\Model */
        $userModel = config('admin.database.users_model');
        /**@var \Illuminate\Database\Eloquent\Model */
        $permissionModel = config('admin.database.permissions_model');
        /**@var \Illuminate\Database\Eloquent\Model */
        $roleModel = config('admin.database.roles_model');

        /**@var \Illuminate\Support\Collection */
        $allPermissions = $permissionModel::all();

        /**@var \Illuminate\Support\Collection 全部角色*/
        $allRoles = $roleModel::all();

        $form = new Form(new $userModel());

        $userTable = config('admin.database.users_table');
        $connection = config('admin.database.connection');

        $form->display('id', 'ID');
        $form->text('username', trans('admin.username'))
            ->creationRules(['required', "unique:{$connection}.{$userTable}"])
            ->updateRules(['required', "unique:{$connection}.{$userTable},username,{{id}}"]);

        $form->text('name', trans('admin.name'))->rules('required');
        $form->image('avatar', trans('admin.avatar'));
        $form->password('password', trans('admin.password'))->rules('required|confirmed');
        $form->password('password_confirmation', trans('admin.password_confirmation'))->rules('required')
            ->default(function ($form) {
                return $form->model()->password;
            });

        $form->ignore(['password_confirmation']);

        $form->multipleSelect('roles', trans('admin.roles'))->options($allRoles->pluck('name', 'id'));
        $form->multipleSelect('permissions', trans('admin.permissions'))->options($allPermissions->pluck('name', 'id'));

        $form->display('created_at', trans('admin.created_at'));
        $form->display('updated_at', trans('admin.updated_at'));

        $form->saving(function (Form $form) use ($allPermissions, $allRoles) {
            if ($form->password && $form->model()->password != $form->password) {
                $form->password = Hash::make($form->password);
            }
            $_permission_slugs = config('admin.only_superadmin_can.permissions', []); // 敏感权限slug
            $_role_slugs = config('admin.only_superadmin_can.roles', []); // 敏感角色slug

            if (Admin::user()->isSuperAdministrator()) {
                //
            } elseif (config('admin.only_superadmin_can.enable')) {
                $_permissions = $allPermissions->whereIn('slug', $_permission_slugs)->pluck('slug', 'id')->toArray();
                $_roles = $allRoles->whereIn('slug', $_role_slugs)->pluck('slug', 'id')->toArray();

                $_permission_tips = [];
                foreach ($form->permissions as $_id) {
                    if (isset($_permissions[intval($_id)])) {
                        $pass = false;
                        $_permission_tips[] = $_permissions[$_id];
                    }
                }
                if ($_permission_tips) {
                    $_permission_tips = implode(',', $_permission_tips);
                    $error = new MessageBag([
                        'title'   => '错误提示',
                        'message' => "包含敏感权限[{$_permission_tips}]，只有超级管理员才可添加编辑",
                    ]);
                    return back()->with(compact('error'));
                }

                $_role_tips = [];
                foreach ($form->roles as $_id) {
                    if (isset($_roles[intval($_id)])) {
                        $_role_tips[] = $_roles[$_id];
                    }
                }
                if ($_role_tips) {
                    $_role_tips = implode(',', $_role_tips);
                    $error = new MessageBag([
                        'title'   => '错误提示',
                        'message' => "包含敏感角色[{$_role_tips}]，只有超级管理员才可添加编辑",
                    ]);
                    return back()->with(compact('error'));
                }
            }
        });

        return $form;
    }
}
